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
    recv_key: Option<Rc4>,
    send_key: Option<Rc4>,
    /// Bytes to serve before reading from the socket
    prefix: Vec<u8>,
    prefix_pos: usize,
}

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
            recv_key,
            send_key,
            prefix,
            prefix_pos: 0,
        }
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

impl AsyncWrite for CryptStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_key.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let mut encrypted = buf.to_vec();
        if let Some(key) = &mut self.send_key {
            key.apply(&mut encrypted);
        }
        // Report the original length so callers see the right number of bytes written
        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
}
