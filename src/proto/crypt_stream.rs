//! CryptStream — transparently encrypted AsyncRead+AsyncWrite over TcpStream.
//!
//! Four construction modes:
//!   plain()                  — no encryption, no prefix
//!   plain_with_prefix()      — no encryption, prefix bytes prepended
//!   encrypted()              — RC4 on both halves, no prefix
//!   encrypted_with_prefix()  — RC4 + prefix (client pipelined a frame)
//!
//! The prefix handles the case where we've already read bytes from the socket
//! (during detection/handshake) but haven't consumed them yet.

use crate::proto::obfuscation::Rc4;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub struct CryptStream {
    inner: TcpStream,
    /// Boxed: an RC4 state is 258 bytes, and the stream lives inside every
    /// connection's task for the whole session. Inline, the two keys made
    /// every connection — obfuscated or not — carry ~0.5 KB, and the async
    /// state machine holds the stream more than once.
    recv_key: Option<Box<Rc4>>,
    send_key: Option<Box<Rc4>>,
    /// Bytes to serve before reading from the socket
    prefix: Vec<u8>,
    prefix_pos: usize,
    /// Ciphertext already produced by `send_key` but not yet taken by the
    /// socket, from `pending_pos` on. RC4 is a stream: every plaintext byte
    /// must be encrypted exactly once, in order, and its ciphertext sent
    /// exactly once. So input is encrypted only when this is empty, and what
    /// the socket did not take is kept here instead of being re-encrypted.
    pending: Vec<u8>,
    pending_pos: usize,
}

/// Plaintext accepted per `poll_write` while encrypting. Bounds the
/// pending-ciphertext buffer; callers (`write_all`, `Framed`) loop on the
/// returned count.
const MAX_ENCRYPT_CHUNK: usize = 64 * 1024;

/// Largest pending-ciphertext capacity kept after it drains (see
/// `poll_drain_pending`). Small on purpose: a client is sent a few frames a
/// minute, so allocating for a large one costs nothing worth saving, while
/// keeping the largest frame's buffer (a source list, a search page — up to
/// 8 KB at the old limit) did, once per obfuscated connection for its whole
/// session. Keepalives, ID changes and server messages fit in this.
const PENDING_KEEP: usize = 512;

impl CryptStream {
    pub fn plain(stream: TcpStream) -> Self {
        Self::new(stream, None, None, vec![])
    }

    pub fn plain_with_prefix(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self::new(stream, None, None, prefix)
    }

    pub fn encrypted(stream: TcpStream, recv_key: Rc4, send_key: Rc4) -> Self {
        Self::new(stream, Some(recv_key), Some(send_key), vec![])
    }

    pub fn encrypted_with_prefix(
        stream: TcpStream,
        recv_key: Rc4,
        send_key: Rc4,
        prefix: Vec<u8>,
    ) -> Self {
        Self::new(stream, Some(recv_key), Some(send_key), prefix)
    }

    fn new(
        inner: TcpStream,
        recv_key: Option<Rc4>,
        send_key: Option<Rc4>,
        prefix: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            recv_key: recv_key.map(Box::new),
            send_key: send_key.map(Box::new),
            prefix,
            prefix_pos: 0,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    /// Heap bytes this stream holds: the pending-ciphertext and prefix
    /// buffers by capacity, and the boxed RC4 states. For /api/memsize.
    pub fn heap_bytes(&self) -> usize {
        let keys = [self.recv_key.is_some(), self.send_key.is_some()]
            .iter()
            .filter(|k| **k)
            .count();
        self.pending.capacity() + self.prefix.capacity() + keys * std::mem::size_of::<Rc4>()
    }

    pub fn is_encrypted(&self) -> bool {
        self.recv_key.is_some()
    }
}

impl AsyncRead for CryptStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain the prefix buffer first
        let remaining_prefix = self.prefix.len().saturating_sub(self.prefix_pos);
        if remaining_prefix > 0 {
            let to_copy = remaining_prefix.min(buf.remaining());
            let start = self.prefix_pos;
            let end = start + to_copy;
            let chunk = &self.prefix[start..end];

            // Decrypt prefix bytes if needed (they came in pre-decrypted
            // from the handshake in the encrypted case, so no extra step needed)
            buf.put_slice(chunk);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Read from socket
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                if let Some(key) = &mut self.recv_key {
                    key.apply(&mut buf.filled_mut()[before..after]);
                }
            }
        }

        result
    }
}

impl CryptStream {
    /// Write out pending ciphertext. Ready(Ok) once it is all taken.
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let n =
                match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_pos += n;
        }
        // Keep a small buffer for the next frame, but give a large one back:
        // one big search result or server list grows this to up to
        // MAX_ENCRYPT_CHUNK, and without the release every obfuscated
        // connection that ever sent one held that much for the rest of its
        // life.
        if self.pending.capacity() > PENDING_KEEP {
            self.pending = Vec::new();
        } else {
            self.pending.clear();
        }
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CryptStream {
    /// Encrypted path, in the manner of eMule's CEncryptedStreamSocket: encrypt
    /// once into a send buffer, send from it, keep the unsent remainder.
    ///
    /// Before, the keystream advanced by `buf.len()` before the socket took
    /// anything. A short write lost the tail while reporting it written; a
    /// `Pending` left the keystream advanced, so the caller's retry encrypted
    /// the same plaintext with the next keystream bytes. Either way the
    /// client's decryption was out of step for the rest of the connection —
    /// what a large search result or server list to a slow obfuscated client
    /// ran into once the socket buffer was full.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_key.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        // Earlier ciphertext goes first. Until it is out, no new input is
        // accepted (and none is encrypted).
        match self.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other.map(|r| r.map(|()| 0)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_ENCRYPT_CHUNK);
        let this = &mut *self;
        this.pending.extend_from_slice(&buf[..take]);
        if let Some(key) = &mut this.send_key {
            key.apply(&mut this.pending);
        }
        // The `take` plaintext bytes are now accepted: their ciphertext is
        // either on the socket or held in `pending` for the next call, flush
        // or shutdown. Try to send it now; an error here ends the connection
        // anyway, and Pending has registered the waker.
        match this.poll_drain_pending(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::obfuscation::Rc4;

    #[test]
    fn rc4_symmetric() {
        let (mut enc, mut dec) = (Rc4::new(b"key", false), Rc4::new(b"key", false));
        let plain = b"Hello obfuscation!";
        let mut buf = plain.to_vec();
        enc.apply(&mut buf);
        assert_ne!(buf.as_slice(), plain.as_slice());
        dec.apply(&mut buf);
        assert_eq!(buf.as_slice(), plain.as_slice());
    }

    /// Push far more encrypted data than the socket buffers hold while the
    /// peer does not read, so the writer meets Pending and short writes; then
    /// read it all and check it decrypts to exactly what was written.
    #[tokio::test]
    async fn encrypted_writes_survive_a_full_socket() {
        use super::CryptStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        const TOTAL: usize = 16 * 1024 * 1024;
        let data: Vec<u8> = (0..TOTAL).map(|i| (i * 31 % 251) as u8).collect();
        let expected = data.clone();

        let writer = tokio::spawn(async move {
            let mut s = CryptStream::encrypted(
                server,
                Rc4::new(b"unused", false),
                Rc4::new(b"send-key", false),
            );
            // Odd-sized writes, so chunk edges never line up with the buffer.
            for chunk in data.chunks(70_001) {
                s.write_all(chunk).await.unwrap();
            }
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        // Let the writer fill both socket buffers before reading anything.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let mut got = Vec::with_capacity(TOTAL);
        let mut client = client;
        client.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();

        let mut dec = Rc4::new(b"send-key", false);
        dec.apply(&mut got);
        assert_eq!(got.len(), expected.len(), "every byte arrives exactly once");
        assert!(got == expected, "the stream decrypts in step end to end");
    }

    #[tokio::test]
    async fn a_large_write_does_not_pin_its_buffer() {
        use super::{CryptStream, PENDING_KEEP};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let reader = tokio::spawn(async move {
            let mut client = client;
            let mut sink = Vec::new();
            client.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });
        let mut s = CryptStream::encrypted(
            server,
            Rc4::new(b"unused", false),
            Rc4::new(b"send-key", false),
        );
        s.write_all(&vec![7u8; 60_000]).await.unwrap();
        s.flush().await.unwrap();
        assert!(s.pending.capacity() <= PENDING_KEEP, "drained big buffer is released");
        // A small frame keeps its buffer for reuse.
        s.write_all(&[1u8; 300]).await.unwrap();
        s.flush().await.unwrap();
        assert!(s.pending.capacity() >= 300);
        s.shutdown().await.unwrap();
        drop(s);
        assert_eq!(reader.await.unwrap(), 60_300);
    }
}
