# dpi-probe

A tool to detect and fingerprint DPI (Deep Packet Inspection) middleboxes by analyzing TLS/SNI behavior and TTL hop patterns across different network targets.

Built and tested from Russia 🇷🇺 — where DPI is part of daily life.

---

## What it does

- Tests TCP RST behavior on port 443
- Sends plain HTTP requests and checks for injection or redirect
- Crafts realistic TLS ClientHello packets with specific SNI values
- Compares server responses to detect silent drops, TLS alerts, and middlebox interference
- Probes TTL hop behavior to fingerprint invisible middleboxes

---

## Real results — Russia, no VPN

### SNI Filtering

Tested against `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google DNS):

| SNI | 1.1.1.1 | 8.8.8.8 | Verdict |
|---|---|---|---|
| google.com | tls_alert | tls_alert | ✓ passes |
| github.com | tls_alert | tls_alert | ✓ passes |
| cloudflare.com | tls_alert | tls_alert | ✓ passes |
| instagram.com | silent_drop | silent_drop | ✗ blocked |
| facebook.com | silent_drop | silent_drop | ✗ blocked |
| twitter.com | silent_drop | silent_drop | ✗ blocked |
| youtube.com | **tls_alert** | silent_drop | ⚠ partial |

### Finding 1 — SNI filtering is active

The DPI reads the SNI field of every TLS ClientHello and silently drops packets destined for blocked domains — regardless of the actual destination IP.

### Finding 2 — SNI + IP correlation

`youtube.com` is blocked toward `8.8.8.8` (Google) but passes through to `1.1.1.1` (Cloudflare). The DPI weighs both the SNI value and the destination IP reputation. Blocking Cloudflare entirely would cause too much collateral damage to legitimate Russian services hosted there.

### Finding 3 — Invisible middleboxes via TTL suppression

Tested with TTL values from 1 to 64 toward `1.1.1.1`:

| TTL | Result |
|---|---|
| 1 | timeout |
| 2 | timeout |
| 3 | timeout |
| 5 | timeout |
| 8 | timeout |
| 13 | connected (6.78ms) |
| 21 | connected (24.03ms) |
| 64 | connected (7.76ms) |

On a normal network, every intermediate router responds with an ICMP TTL Exceeded message — making hops visible and countable. Here, nothing responds between hop 1 and hop 13.

The intermediate infrastructure is **deliberately silent**. This is not a misconfiguration — it is by design. The middleboxes suppressing ICMP are the same ones performing SNI inspection.

---

## Why this matters

These three findings together confirm an active, sophisticated, and deliberately opaque DPI infrastructure. The filtering is not based on SNI alone — it correlates SNI with destination IP, and the equipment performing this inspection is engineered to remain invisible to standard network diagnostics.

This is exactly the attack surface that **VLESS + Reality** bypasses: by borrowing a legitimate TLS identity, the SNI field becomes meaningless to the inspector.

---

## Usage

```bash
py main.py <target_ip>
# or
python main.py <target_ip>
```

---

## Stack

- Python 3.11+
- Raw sockets — no external dependencies

---

## Roadmap

- [ ] TCP RST origin fingerprinting
- [ ] TLS ClientHello malformation test
- [ ] JSON report output
- [ ] Auto-detect local DPI presence
- [ ] Map hop count vs RTT to estimate middlebox distance

---

## Author

[allanjoshuaf](https://github.com/allanjoshuaf)