//! Tools for checking your public IP and verifying you're really going through Tor.
//!
//! All network requests here are routed through Tor's SOCKS5 proxy using curl.
//! This means even the check requests themselves are anonymous — we're not
//! reaching out to any external service over your real IP.

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::config::{IP_CHECK_URLS, RESOLV_PATH, SOCKS_PORT, TOR_CHECK_URL};
use crate::{info, ok, warn};

// ─── Response type ───────────────────────────────────────────────────────────

/// The JSON response from check.torproject.org/api/ip.
/// Example: `{"IsTor": true, "IP": "185.220.101.5"}`
#[derive(Deserialize)]
struct TorCheckResponse {
    #[serde(rename = "IsTor")]
    is_tor: bool,
    #[serde(rename = "IP")]
    ip: String,
}

// ─── Internal helper ─────────────────────────────────────────────────────────

/// Make an HTTP request through Tor's SOCKS5 proxy using curl.
///
/// We use `socks5h://` (with the 'h') which tells curl to also resolve
/// the hostname through the proxy — this prevents DNS leaks where your
/// system DNS would reveal what domain you're connecting to.
fn curl_via_tor(url: &str, timeout: u64) -> Result<String> {
    let socks = format!("socks5h://127.0.0.1:{}", SOCKS_PORT);
    let timeout_str = timeout.to_string();

    // Tor's SOCKS port may accept TCP connections before it has finished
    // bootstrapping internally. We retry a few times so transient proxy
    // errors (curl exit 97 = CURLE_PROXY) don't cause a false failure.
    const MAX_RETRIES: u32 = 5;
    const RETRY_DELAY: Duration = Duration::from_secs(2);

    let mut last_err = String::new();

    for attempt in 1..=MAX_RETRIES {
        let output = Command::new("curl")
            .args(&[
                "--silent",
                "--max-time", &timeout_str,
                "--proxy", &socks,
                url,
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
            .context("failed to run curl")?;

        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        last_err = output.status.to_string();

        if attempt < MAX_RETRIES {
            tracing::debug!(
                "curl attempt {}/{} failed ({}), retrying in {}s…",
                attempt, MAX_RETRIES, last_err, RETRY_DELAY.as_secs()
            );
            sleep(RETRY_DELAY);
        }
    }

    bail!("curl exited with {} — is Tor running and ready?", last_err);
}

// ─── Tor circuit check ───────────────────────────────────────────────────────

/// Ask the Tor Project's API whether your current connection exits through Tor.
///
/// This gives us a reliable yes/no answer plus your current exit IP address.
/// We parse the JSON response properly rather than doing string matching,
/// which could give a false positive if the response format changed.
pub fn verify_tor_circuit() -> Result<String> {
    info!("Verifying Tor circuit via check.torproject.org…");

    let body = curl_via_tor(TOR_CHECK_URL, 15)?;

    let resp: TorCheckResponse = serde_json::from_str(&body)
        .with_context(|| format!("unexpected response from {}: {}", TOR_CHECK_URL, body.trim()))?;

    if resp.is_tor {
        ok!("Traffic is going through Tor — exit IP: {}", resp.ip);
        Ok(resp.ip)
    } else {
        bail!(
            "Tor circuit check FAILED — IsTor=false, IP={}\n  \
             Traffic is NOT going through Tor",
            resp.ip
        )
    }
}

// ─── Public IP lookup ────────────────────────────────────────────────────────

/// Get your current public IP address by trying each URL in the list.
///
/// We try the check.torproject.org endpoint first (JSON response),
/// then fall back to plain-text IP services. Returns the first one that works.
pub fn get_public_ip() -> Result<String> {
    for url in IP_CHECK_URLS {
        match curl_via_tor(url, 10) {
            Ok(body) => {
                if url.contains("check.torproject.org") {
                    // This endpoint returns JSON — parse it properly.
                    if let Ok(resp) = serde_json::from_str::<TorCheckResponse>(&body) {
                        return Ok(resp.ip);
                    }
                } else {
                    // Other endpoints return a plain IP address as plain text.
                    let ip = body.trim().to_string();
                    if !ip.is_empty() {
                        return Ok(ip);
                    }
                }
            }
            Err(e) => tracing::warn!("IP check via {} failed: {}", url, e),
        }
    }

    bail!("could not retrieve public IP — all endpoints failed");
}

// ─── DNS leak check ──────────────────────────────────────────────────────────

/// Check that DNS queries are going through Tor and not leaking to your ISP.
///
/// A DNS leak happens when your system resolves domain names using a normal
/// DNS server instead of Tor's DNS port. Even if all your TCP traffic goes
/// through Tor, a DNS leak reveals which websites you're visiting to your ISP.
///
/// We do two checks:
/// 1. `/etc/resolv.conf` must only contain `nameserver 127.0.0.1`.
///    Any other nameserver would bypass Tor's DNS entirely.
/// 2. We try an actual DNS resolution through the Tor SOCKS proxy to
///    confirm Tor's DNS port is answering requests.
pub fn dns_leak_check() -> Result<()> {
    info!("Running DNS leak check…");

    // Check 1: Look at resolv.conf and flag any non-local nameservers.
    let resolv = std::fs::read_to_string(RESOLV_PATH)
        .with_context(|| format!("cannot read {}", RESOLV_PATH))?;

    let non_tor_ns: Vec<&str> = resolv
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .filter(|l| !l.contains("127.0.0.1"))
        .collect();

    if !non_tor_ns.is_empty() {
        bail!(
            "DNS LEAK DETECTED — {} contains non-Tor nameservers:\n  {}",
            RESOLV_PATH,
            non_tor_ns.join("\n  ")
        );
    }

    ok!("{} correctly points to 127.0.0.1", RESOLV_PATH);

    // Check 2: Make a real DNS request through the SOCKS proxy.
    // Using socks5h:// forces curl to resolve the hostname through Tor too,
    // so if this succeeds we know Tor's DNS port is actually working.
    let socks = format!("socks5h://127.0.0.1:{}", SOCKS_PORT);
    let result = Command::new("curl")
        .args(&[
            "--silent",
            "--max-time", "10",
            "--proxy", &socks,
            "--head",           // We only care about the response code, not the body.
            "--output", "/dev/null",
            "--write-out", "%{http_code}",
            "https://check.torproject.org/",
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .context("curl DNS probe failed")?;

    let code = String::from_utf8_lossy(&result.stdout);
    if result.status.success() && (code.starts_with('2') || code.starts_with('3')) {
        ok!("DNS resolves through Tor (HTTP {})", code.trim());
    } else {
        // A failure here isn't necessarily a leak — Tor might still be warming up.
        warn!(
            "DNS probe returned unexpected status {} — \
             DNS may not be flowing through Tor yet (Tor still starting?)",
            code.trim()
        );
    }

    Ok(())
}
