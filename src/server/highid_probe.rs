//! HighID/LowID detection probe (SPEC.md §3.2).
//!
//! The server opens an outbound TCP connection to (client_ip, client_port).
//! If successful → HighID (client is reachable, assigned_id = IPv4 as u32).
//! If timeout/refused → LowID (client is behind NAT, assigned_id from pool).
//!
//! The server sends OP_HELLO (eD2k client-to-client opcode 0x01 with prefix
//! 0x10) during the test, then closes. The client ignores it but the TCP
//! handshake itself proves reachability.
//!
//! This is the standard eD2k callback reachability check (server connects back
//! to the client to learn whether it has an open port); it is NOT a backdoor.
//!
//! Config: `network.login_timeout_ms` (default 2000ms).
//! On busy servers this runs concurrently per connection — no global lock.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// Probe the client's advertised (ip, port).
/// Returns true if the client is routable (HighID).
pub async fn probe(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    // Private / loopback / link-local are always LowID — no point probing.
    if !is_routable(ip) {
        debug!(ip = %ip, "private IP → LowID without probe");
        return false;
    }

    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            // Connected — HighID. Stream is immediately dropped; the client
            // will see a brief incoming connection which it handles gracefully.
            debug!(addr = %addr, "HighID probe succeeded → HighID");
            true
        }
        Ok(Err(e)) => {
            debug!(addr = %addr, error = %e, "HighID probe refused → LowID");
            false
        }
        Err(_) => {
            debug!(addr = %addr, "HighID probe timeout → LowID");
            false
        }
    }
}

/// Compute the HighID from an IPv4 address.
/// eD2k uses the raw u32 (big-endian octets interpreted as little-endian u32).
pub fn high_id_from_ip(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Stored as u32 LE: octets in natural order
            Some(u32::from_le_bytes(octets))
        }
        _ => None,
    }
}

fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
        }
        IpAddr::V6(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn private_ips_not_routable() {
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(172, 23, 20, 152))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn public_ip_routable() {
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(65, 109, 199, 83))));
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn high_id_encoding() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let id = high_id_from_ip(ip).unwrap();
        // LE bytes of [1,2,3,4] = 0x04030201
        assert_eq!(id, 0x04030201);
    }
}
