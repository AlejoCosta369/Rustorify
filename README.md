<p align="center">
  <img src="banner.png" alt="Rustorify" width="600"/>
</p>

# rustorify

A transparent proxy through [Tor](https://www.torproject.org/) for Linux, written in Rust. Routes all TCP traffic through the Tor network using `iptables` rules, providing system-wide anonymity.

This is a modern, memory-safe rewrite of [kalitorify](https://github.com/brainfucksec/kalitorify) in Rust.

## Features

- Routes **all TCP traffic** through Tor transparently (no per-app config needed)
- DNS queries routed through Tor (no DNS leaks)
- IPv6 fully blocked (Tor does not support transparent proxying over IPv6)
- Optional **kill switch**: if Tor stops, internet is cut off automatically
- Live circuit verification against `check.torproject.org`
- Atomic file operations and automatic backup/restore of system files
- Graceful Ctrl-C handling with automatic cleanup

## Requirements

- Linux (uses `/proc`, `iptables`, `systemctl`)
- [Tor](https://www.torproject.org/) installed and managed by systemd
- `iptables` and `ip6tables`
- `curl`
- Root privileges

> Tested on Debian/Ubuntu/Kali-based systems. The Tor daemon must run as the `debian-tor` user.

## Installation

### Automated (recommended)

```bash
git clone https://github.com/yourusername/rustorify
cd rustorify
sudo bash install.sh
```

The script will automatically:
- Install system dependencies (`tor`, `iptables`, `curl`) via `apt`
- Install Rust/Cargo if not present
- Compile the binary in release mode
- Install the binary and data files to the correct paths

> Only supports Debian/Ubuntu/Kali-based systems.

### From source (manual)

```bash
git clone https://github.com/yourusername/rustorify
cd rustorify
cargo build --release
sudo cp target/release/rustorify /usr/local/bin/
sudo mkdir -p /usr/share/rustorify/data
sudo cp data/torrc /usr/share/rustorify/data/torrc
```

### Dependencies (Cargo)

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `anyhow` | Error handling |
| `colored` | Colored terminal output |
| `serde` / `serde_json` | JSON parsing for Tor API |
| `tracing` / `tracing-subscriber` | Structured logging |
| `ctrlc` | Graceful interrupt handling |

## Usage

All commands require root privileges.

```bash
# Enable transparent proxy through Tor
sudo rustorify --tor

# Enable with kill switch (cuts internet if Tor stops)
sudo rustorify --tor --kill-switch

# Disable proxy and restore original network configuration
sudo rustorify --clearnet

# Get a new Tor circuit (new exit IP)
sudo rustorify --restart

# Check proxy status and verify Tor circuit
sudo rustorify --status

# Show current public IP address
sudo rustorify --ipinfo
```

### CLI Options

| Flag | Short | Description |
|------|-------|-------------|
| `--tor` | `-t` | Enable transparent proxy through Tor |
| `--clearnet` | `-c` | Disable proxy, restore original config |
| `--restart` | `-r` | Restart Tor (get new circuit/IP) |
| `--status` | `-s` | Show current status and verify circuit |
| `--ipinfo` | `-i` | Show current public IP |
| `--kill-switch` | `-k` | Install kill switch (use with `--tor`) |
| `--log-level` | | Logging verbosity: `off`, `error`, `warn`, `info`, `debug`, `trace` |

## How It Works

When `--tor` is enabled:

1. Backs up `/etc/tor/torrc` and `/etc/resolv.conf`
2. Installs a Tor config with `TransPort 9040` and `DNSPort 5353`
3. Starts the Tor service and waits for readiness (polls SOCKS port 9050)
4. Blocks all IPv6 via `iptables` and `sysctl`
5. Installs `iptables` rules that redirect all TCP to `TransPort` and DNS to `DNSPort`
6. Optionally installs a systemd drop-in kill switch

When `--clearnet` is run, all changes are fully reversed and original files are restored from backups.

### Traffic not routed through Tor

Private and local address ranges are excluded from redirection:

```
127.0.0.0/8      (loopback)
10.0.0.0/8       (private)
172.16.0.0/12    (private)
192.168.0.0/16   (private)
169.254.0.0/16   (link-local)
224.0.0.0/4      (multicast)
240.0.0.0/4      (reserved)
```

### Tor configuration

The bundled `torrc` configures:

- `TransPort 9040` — TCP redirection
- `DNSPort 5353` — Anonymous DNS resolution
- `SocksPort 9050 IsolateClientAddr IsolateDestAddr IsolateDestPort` — Circuit isolation per app
- `VirtualAddrNetworkIPv4 10.192.0.0/10` — For `.onion` address routing

## Project Structure

```
rustorify/
├── Cargo.toml
├── install.sh             # Automated install script (Debian/Ubuntu/Kali)
├── data/
│   └── torrc              # Bundled Tor configuration
└── src/
    ├── main.rs            # Entry point and command dispatch
    ├── cli.rs             # CLI definition (clap)
    ├── config.rs          # Constants (ports, paths, timeouts)
    ├── tor.rs             # Tor service control (systemctl)
    ├── firewall.rs        # iptables/ip6tables rule management
    ├── files.rs           # Backup/restore and state management
    ├── ipinfo.rs          # Circuit verification and IP lookup
    ├── checks.rs          # Pre-flight checks (root, dependencies)
    ├── lock.rs            # Lock file to prevent parallel instances
    └── output.rs          # Colored output macros
```

## System Paths

| Path | Description |
|------|-------------|
| `/usr/local/bin/rustorify` | Binary |
| `/usr/share/rustorify/data/torrc` | Bundled Tor config |
| `/var/lib/rustorify/backups/` | Automatic backups |
| `/var/lib/rustorify/state` | Current state (`active`/`inactive`) |
| `/var/run/rustorify.lock` | Lock file |
| `/etc/systemd/system/tor.service.d/` | Kill switch drop-in |

## Disclaimer

This tool modifies system-level network configuration and requires root privileges. Use responsibly and only on systems you own or have permission to configure. Routing traffic through Tor does not guarantee complete anonymity — see the [Tor Project's documentation](https://www.torproject.org/about/overview) for details and limitations.

## License

[GPL-3.0](LICENSE)
