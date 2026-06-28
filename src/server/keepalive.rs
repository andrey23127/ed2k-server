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

pub fn spawn_keepalive(state: Arc<ServerState>, ping_delay_seconds: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(ping_delay_seconds);
        loop {
            tokio::time::sleep(interval).await;

            let users = state.client_count() as u32;
            let files = state.file_count() as u32;
            let connected = users; // snapshot before we iterate

            let mut payload = BytesMut::with_capacity(8);
            payload.put_u32_le(users);
            payload.put_u32_le(files);
            let frame = Frame::new(OP_SERVERSTATUS, payload.to_vec());

            // Send to every connected client via their mpsc channel
            let mut pinged = 0u32;
            for entry in state.clients.iter() {
                entry.send_frame(frame.clone());
                pinged += 1;
            }

            if pinged > 0 {
                debug!(pinged, users = connected, files, "keepalive sent");
            }
        }
    });
}
