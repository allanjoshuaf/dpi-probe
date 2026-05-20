# dpi-probe

A tool to detect and fingerprint DPI (Deep Packet Inspection) middleboxes by analyzing TLS/SNI behavior, TTL hop patterns, RST origin timing, and malformed TLS responses.

Built and tested from Russia 🇷🇺 - where DPI is part of daily life.

---

## What it does

- Tests TCP RST behavior on port 443
- Sends plain HTTP requests and checks for injection or redirect
- Crafts realistic TLS ClientHello packets with specific SNI values
- Compares server responses to detect silent drops, TLS alerts, and middlebox interference
- Probes TTL hop behavior to fingerprint invisible middleboxes
- Measures RST timing to determine if resets come from the real server or an interceptor
- Sends intentionally malformed TLS ClientHello packets to fingerprint the middlebox parser
- Generates a scored JSON report with confidence level

---

## Real results - Russia, no VPN

### Test 1 - SNI Filtering

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

**Finding 1 - SNI filtering is active**
The DPI reads the SNI field of every TLS ClientHello and silently drops packets for blocked domains regardless of the actual destination IP.

**Finding 2 - SNI + IP correlation**
`youtube.com` is blocked toward `8.8.8.8` but passes through to `1.1.1.1`. The DPI weighs both SNI and destination IP reputation. Blocking Cloudflare entirely would cause too much collateral damage to legitimate Russian services hosted there.

---

### Test 2 - TTL Hop Analysis

| TTL | 1.1.1.1 | 8.8.8.8 |
|---|---|---|
| 1 | timeout | timeout |
| 2 | timeout | timeout |
| 3 | timeout | timeout |
| 5 | timeout | timeout |
| 8 | timeout | timeout |
| 13 | connected (30ms) | timeout |
| 21 | connected (7ms) | connected (27ms) |
| 64 | connected (7ms) | connected (32ms) |

**Finding 3 - Invisible middleboxes**
On a normal network every intermediate router responds with ICMP TTL Exceeded. Here nothing responds between hop 1 and hop 13 (Cloudflare) or hop 21 (Google). The infrastructure is deliberately silent - engineered to remain invisible to standard network diagnostics.

---

### Test 3 - RST Origin Fingerprinting

| Target | Baseline RTT | RST Timing | Ratio | Verdict |
|---|---|---|---|---|
| 1.1.1.1 | 31.08ms | 9.65ms | 0.30x | **middlebox** |
| 8.8.8.8 | 22.32ms | 24.43ms | 1.09x | ambiguous |

**Finding 4 - Middlebox caught responding on 1.1.1.1**
When sending a request with a blocked Host header toward `1.1.1.1`, the response arrives in 9.65ms while the baseline RTT to Cloudflare is ~31ms. Something physically closer than Cloudflare responded in our place.

---

### Test 4 - Malformed TLS ClientHello

| Variant | Response | Alert Code | RTT |
|---|---|---|---|
| wrong_version | tls_alert | 0x28 (handshake_failure) | 12.15ms |
| empty_ciphers | tls_alert | 0x32 (decode_error) | 8.09ms |
| oversized_sni | tls_alert | 0x32 (decode_error) | 9.99ms |
| truncated | tls_alert | 0x32 (decode_error) | 7.96ms |
| duplicate_sni | tls_alert | 0x32 (decode_error) | 10.17ms |

**Finding 5 — Middlebox TLS parser fingerprinted**
All malformed responses arrive in 8-12ms against a 30ms baseline; the middlebox is responding, not Cloudflare. It runs a full TLS parser that understands and correctly codes protocol errors.

---

### Final report output

```
==================================================
DPI PROBE REPORT
Target     : 1.1.1.1
Timestamp  : 2026-05-20T21:54:28Z
DPI detected  : YES
Confidence    : HIGH
Score         : 10/10
Findings :
→ SNI silent drop detected for: instagram.com, facebook.com, twitter.com
→ Silent drop at TTL [1, 2, 3, 5, 8] before connection - middlebox interference
→ RST from middlebox response at 9.65ms vs 32.07ms baseline
→ Malformed TLS responses faster than baseline middlebox TLS parser active
```

## Why this matters

These five findings together confirm an active, sophisticated, and deliberately opaque DPI infrastructure that filters on SNI, correlates with destination IP reputation, suppresses ICMP to hide its presence, injects responses faster than the real destination, and runs a full TLS parser capable of correctly handling malformed packets.

This is exactly the attack surface that **VLESS + Reality** bypasses: by borrowing a legitimate TLS identity, the SNI field becomes meaningless to the inspector.

---

## Usage

```bash
py main.py <target_ip>
# or
python main.py <target_ip>
```

A JSON report is automatically saved to the current directory.

---

## Stack

- Python 3.11+
- Raw sockets - no external dependencies

---

## Roadmap

- [x] TCP RST behavior test
- [x] SNI fingerprinting
- [x] TTL hop analysis
- [x] RST origin fingerprinting
- [x] Malformed TLS ClientHello test
- [x] JSON report output
- [ ] Auto-detect local DPI presence
- [ ] Map hop count vs RTT to estimate middlebox distance

---

## Author

[allanjoshuaf](https://github.com/allanjoshuaf)