//! Keepalive task (SPEC.md §3.7).
//!
//! Sends OP_SERVERSTATUS to every connected client every `ping_delay_seconds`.
//! This tells clients the server is still alive and shows current user/file counts.
//! Clients that don't receive a ping within their timeout period disconnect.
//!
//! Implemented as a background tokio task that runs a simple interval loop.

use crate::proto::{opcodes::OP_SERVERSTATUS, Frame};
use crate::state::ServerState;
use bytes::{BufMut, BytesMut};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Number of slices one keepalive round is spread over.
///
/// Every client is still pinged once per `ping_delay_seconds`, but in slices
/// a few seconds apart instead of all at once: at 50k clients the single burst
/// woke every connection task in the same instant, wrote 50k frames back to
/// back and showed up as a regular CPU spike every interval.
const SLICES: u64 = 60;

/// Which slice a client belongs to. Fixed by its user hash, so a client is in
/// the same slice every round and keeps a steady interval between its pings.
fn slice_of(user_hash: &[u8; 16], slices: u64) -> u64 {
    u64::from(user_hash[0] ^ user_hash[7] ^ user_hash[15]) % slices
}

pub fn spawn_keepalive(state: Arc<ServerState>, ping_delay_seconds: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(ping_delay_seconds.max(1));
        // Fewer slices on a very short interval (tests use 1 s), at least
        // ~1 s apart otherwise.
        let slices = SLICES.min(ping_delay_seconds.max(1));
        let step = interval / slices as u32;
        let mut slice = 0u64;
        loop {
            tokio::time::sleep(step).await;

            let users = state.client_count() as u32;
            let files = state.file_count() as u32;

            let mut payload = BytesMut::with_capacity(8);
            payload.put_u32_le(users);
            payload.put_u32_le(files);
            let frame = Frame::new(OP_SERVERSTATUS, payload.to_vec());

            // Send to this slice's connected clients via their mpsc channel.
            let mut pinged = 0u32;
            for entry in state.clients.iter() {
                if slice_of(entry.key(), slices) != slice {
                    continue;
                }
                let outcome = entry.send_frame(frame.clone());
                state
                    .admission
                    .push
                    .note(crate::admission::PushKind::Keepalive, outcome);
                pinged += 1;
            }

            if pinged > 0 {
                debug!(pinged, slice, users, files, "keepalive sent");
            }
            slice = (slice + 1) % slices;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_cover_every_client_once_and_evenly() {
        let mut counts = vec![0u32; SLICES as usize];
        for i in 0..60_000u32 {
            let mut h = [0u8; 16];
            h[0..4].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_le_bytes());
            h[7] = (i >> 3) as u8;
            h[15] = (i >> 11) as u8;
            counts[slice_of(&h, SLICES) as usize] += 1;
        }
        let (min, max) = (*counts.iter().min().unwrap(), *counts.iter().max().unwrap());
        assert!(min > 0 && max < min * 2, "uneven slices: {min}..{max}");
        // A one-second interval still pings everyone each round.
        assert_eq!(SLICES.min(1), 1);
        assert_eq!(slice_of(&[0xAB; 16], 1), 0);
    }
}
