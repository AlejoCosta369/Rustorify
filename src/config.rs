//! All the constants used across the project.
//!
//! Keeping everything in one place makes it easy to change ports,
//! paths, or timeouts without hunting through multiple files.

// ─── Network ports ─────────────────────────────────────────────────────────

/// The TCP port where Tor accepts redirected traffic (transparent proxy mode).
pub const TRANS_PORT: u16 = 9040;

/// The UDP port where Tor handles DNS queries, so lookups go through Tor too.
pub const DNS_PORT: u16 = 5353;

/// The SOCKS5 port — we use this to check whether Tor has finished starting up.
pub const SOCKS_PORT: u16 = 9050;

/// The virtual IP range Tor uses internally to route .onion addresses.
pub const VIRTUAL_ADDR: &str = "10.192.0.0/10";

/// The system user that runs the Tor daemon on Debian/Ubuntu/Kali.
/// We need this so we can exempt Tor's own traffic from the redirect rules
/// (otherwise Tor would try to send its traffic through itself — not good).
pub const TOR_USER: &str = "debian-tor";

/// Networks that should never be routed through Tor.
/// This covers your local network, loopback, link-local, multicast, etc.
/// Without these exceptions, you'd lose access to your router and local devices.
pub const NON_TOR_NETS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",  // link-local
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved
];

// ─── File paths ─────────────────────────────────────────────────────────────

/// Where the bundled torrc config file lives after installation.
pub const DATA_DIR: &str = "/usr/share/rustorify/data";

/// Where we store backups of files we modify (torrc, resolv.conf).
pub const BACKUP_DIR: &str = "/var/lib/rustorify/backups";

/// A small file that records whether the proxy is currently active or not.
/// We check this to prevent accidentally running --tor twice, or --clearnet
/// when nothing is running.
pub const STATE_FILE: &str = "/var/lib/rustorify/state";

/// Lock file that prevents two instances from running at the same time.
pub const LOCK_FILE: &str = "/var/run/rustorify.lock";

/// The main Tor config file we modify when enabling the transparent proxy.
pub const TORRC_PATH: &str = "/etc/tor/torrc";

/// The system DNS config file. We point this at Tor's DNS port so name
/// lookups also go through Tor, not your ISP's DNS.
pub const RESOLV_PATH: &str = "/etc/resolv.conf";

/// Backup of the original torrc, restored when you run --clearnet.
pub const TORRC_BACKUP: &str = "/var/lib/rustorify/backups/torrc.backup";

/// Backup of the original resolv.conf, restored when you run --clearnet.
pub const RESOLV_BACKUP: &str = "/var/lib/rustorify/backups/resolv.conf.backup";

/// If /etc/resolv.conf was a symlink (e.g. managed by systemd-resolved),
/// this file stores the symlink target so --clearnet can restore the symlink
/// rather than leaving a plain file in its place.
#[cfg_attr(not(unix), allow(dead_code))]
pub const RESOLV_LINK_BACKUP: &str = "/var/lib/rustorify/backups/resolv.conf.link";

/// Folder for the systemd "drop-in" file that powers the kill switch feature.
pub const KILLSWITCH_DROPIN_DIR: &str = "/etc/systemd/system/tor.service.d";

/// The actual drop-in config file. When installed, systemd will automatically
/// run `rustorify --clearnet` if the Tor service ever stops unexpectedly,
/// so traffic is blocked rather than falling back to your real IP.
pub const KILLSWITCH_DROPIN_FILE: &str =
    "/etc/systemd/system/tor.service.d/kalitorify-killswitch.conf";

/// Temporary marker file used to suppress the kill switch during an intentional
/// Tor restart or shutdown that rustorify itself initiated.
pub const KILLSWITCH_BYPASS_FILE: &str = "/run/rustorify.skip-clearnet";

// ─── IPv6 sysctl keys ───────────────────────────────────────────────────────

/// These kernel settings completely disable the IPv6 stack.
/// We use them alongside ip6tables rules — ip6tables filters IPv6 packets,
/// but sysctl goes further and stops the kernel from even using IPv6 at all.
pub const SYSCTL_IPV6_KEYS: &[&str] = &[
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
    "net.ipv6.conf.lo.disable_ipv6",
];

// ─── External URLs ──────────────────────────────────────────────────────────

/// Tor Project's official API to check if you're connected through Tor.
/// Returns JSON like: {"IsTor": true, "IP": "1.2.3.4"}
pub const TOR_CHECK_URL: &str = "https://check.torproject.org/api/ip";

/// A list of URLs we try when fetching your public IP address.
/// We try them in order and return the first one that works.
pub const IP_CHECK_URLS: &[&str] = &[
    "https://check.torproject.org/api/ip",
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
];

// ─── Timeouts ───────────────────────────────────────────────────────────────

/// How long to wait (in seconds) for Tor to finish bootstrapping after we start it.
/// If Tor takes longer than this, we give up and report an error.
pub const TOR_READY_TIMEOUT_SECS: u64 = 30;
