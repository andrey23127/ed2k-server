//! Scanners into the IP filter, for good.
//!
//! A source the bot detector banned that keeps sending through its whole ban
//! (`bots.ipfilter_min_dropped` dropped datagrams) does not read the answers:
//! it is a scanner walking a list, not a client. It gets a line in the IP
//! filter file (`storage.ipfilter_path`, guarding.p2p format):
//!
//! ```text
//! 071.231.168.221 - 071.231.168.221 , 000 , bot
//! ```
//!
//! The line is appended only when no line already covers the address, and
//! the filter is reloaded in memory at once (TCP and UDP both consult it).
//!
//! The file may be replaced later (the update service installs a new
//! guarding.p2p whole). So every address added is also recorded in
//! `bot-ipfilter.txt` next to the config, and put back into the filter file
//! before each load of it: at startup and on every reload.

use crate::state::ServerState;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Description given to the lines this module writes.
pub const TAG: &str = "bot";

/// `071.231.168.221 - 071.231.168.221 , 000 , bot`
pub fn format_line(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    let a = format!("{:03}.{:03}.{:03}.{:03}", o[0], o[1], o[2], o[3]);
    format!("{a} - {a} , 000 , {TAG}")
}

/// Where the list of added addresses lives: next to the config file.
pub fn list_path(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join("bot-ipfilter.txt")
}

/// Is `ip` already covered by a line of `content`? Any line, ours or not: a
/// range that already blocks the address needs no second line.
fn covered(content: &str, ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    content.lines().any(|l| {
        let l = l.trim();
        !l.is_empty()
            && !l.starts_with('#')
            && crate::filter::ipfilter::parse_line(l).is_some_and(|(s, e)| s <= n && n <= e)
    })
}

/// Append the line for `ip` to the filter file unless a line already covers
/// it. Returns whether a line was written. A missing file is created.
pub fn append_if_missing(filter: &Path, ip: Ipv4Addr) -> std::io::Result<bool> {
    let content = match std::fs::read(filter) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if covered(&content, ip) {
        return Ok(false);
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(filter)?;
    let sep = if content.is_empty() || content.ends_with('\n') { "" } else { "\n" };
    writeln!(f, "{sep}{}", format_line(ip))?;
    Ok(true)
}

/// Record `ip` in the list of added addresses, once.
fn remember(list: &Path, ip: Ipv4Addr) -> std::io::Result<()> {
    let have = std::fs::read_to_string(list).unwrap_or_default();
    let key = ip.to_string();
    if have.lines().any(|l| l.split_whitespace().next() == Some(key.as_str())) {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(list)?;
    let when = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    writeln!(f, "{key} {when}")
}

/// Put every recorded address back into the filter file (those a replaced
/// file lost). Returns how many lines were written.
pub fn reassert(filter: &Path, list: &Path) -> usize {
    let Ok(text) = std::fs::read_to_string(list) else { return 0 };
    let mut n = 0;
    for ip in text.lines().filter_map(|l| l.split_whitespace().next()?.parse::<Ipv4Addr>().ok()) {
        match append_if_missing(filter, ip) {
            Ok(true) => n += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(path = %filter.display(), error = %e, "bot ipfilter: cannot write");
                break;
            }
        }
    }
    n
}

/// Add `ip` to the IP filter and reload it, off the caller's thread. A no-op
/// without `storage.ipfilter_path` or outside a runtime.
pub fn add_async(state: &std::sync::Arc<ServerState>, ip: Ipv4Addr) {
    let filter_path = state.live_cfg.load().storage.ipfilter_path.clone();
    if filter_path.is_empty() {
        tracing::info!(%ip, "bot ipfilter: no storage.ipfilter_path, not added");
        return;
    }
    let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
    let list = state.bot_ipfilter_list.get().cloned().flatten();
    let state = std::sync::Arc::clone(state);
    rt.spawn(async move {
        let path = PathBuf::from(&filter_path);
        let p2 = path.clone();
        let res = tokio::task::spawn_blocking(move || {
            let added = append_if_missing(&p2, ip)?;
            if let Some(l) = &list {
                if let Err(e) = remember(l, ip) {
                    tracing::warn!(path = %l.display(), error = %e, "bot ipfilter: cannot record");
                }
            }
            let f = crate::filter::ipfilter::IpFilter::load(&p2);
            Ok::<_, std::io::Error>((added, f))
        })
        .await;
        match res {
            Ok(Ok((added, f))) => {
                *state.ip_filter.write().await = f;
                *state.block_stats.entry("bot_ipfilter".to_string()).or_insert(0) += 1;
                tracing::warn!(%ip, added, path = %path.display(),
                    "bot added to the IP filter (kept sending through its ban)");
            }
            Ok(Err(e)) => tracing::warn!(%ip, error = %e, path = %path.display(),
                "bot ipfilter: cannot write the filter file"),
            Err(e) => tracing::warn!(%ip, error = %e, "bot ipfilter: task failed"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_has_the_guarding_format() {
        assert_eq!(
            format_line("71.231.168.221".parse().unwrap()),
            "071.231.168.221 - 071.231.168.221 , 000 , bot"
        );
        let (s, e) = crate::filter::ipfilter::parse_line(&format_line("1.2.3.4".parse().unwrap()))
            .expect("our own line parses");
        assert_eq!((s, e), (0x0102_0304, 0x0102_0304));
    }

    #[test]
    fn a_line_is_added_once_and_not_over_a_covering_range() {
        let dir = std::env::temp_dir().join(format!("botipf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("guarding.p2p");
        // No trailing newline on purpose.
        std::fs::write(&f, "050.058.238.000 - 050.058.238.255 , 000 , Level 3 botnet").unwrap();
        let ip: Ipv4Addr = "71.231.168.221".parse().unwrap();
        assert!(append_if_missing(&f, ip).unwrap());
        assert!(!append_if_missing(&f, ip).unwrap(), "already there");
        // Covered by an existing range: nothing written.
        assert!(!append_if_missing(&f, "50.58.238.7".parse().unwrap()).unwrap());
        let text = std::fs::read_to_string(&f).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(text.lines().nth(1), Some(format_line(ip).as_str()));
        let filt = crate::filter::ipfilter::IpFilter::load(&f);
        assert!(filt.is_blocked(ip));

        // A replaced file gets the recorded addresses back.
        let list = dir.join("bot-ipfilter.txt");
        remember(&list, ip).unwrap();
        remember(&list, ip).unwrap();
        assert_eq!(std::fs::read_to_string(&list).unwrap().lines().count(), 1);
        std::fs::write(&f, "001.000.000.000 - 001.000.000.255 , 000 , other\n").unwrap();
        assert_eq!(reassert(&f, &list), 1);
        assert_eq!(reassert(&f, &list), 0);
        assert!(crate::filter::ipfilter::IpFilter::load(&f).is_blocked(ip));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
