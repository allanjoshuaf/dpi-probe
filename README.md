# dpi-probe

A tool to detect and fingerprint traffic interference on the local network path. It tests whether TLS SNI, destination IP, HTTP Host headers, malformed TLS payloads, or TCP resets are being filtered, dropped, injected, or modified by a DPI/middlebox.

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
- Auto-detects local DPI presence without requiring a target argument

---

## Real results - Russia

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

**Finding 5 - Middlebox TLS parser fingerprinted**
All malformed responses arrive in 8-12ms against a 30ms baseline; the middlebox is responding, not Cloudflare. It runs a full TLS parser that understands and correctly codes protocol errors.

---

### Test 5 - Auto-detection across 3 network conditions

The most revealing test: running auto-detect under AdGuard VPN, no VPN, and VLESS Reality (Sing-box).

| Condition | SNI drops | RST ratio | DPI detected | Note |
|---|---|---|---|---|
| AdGuard VPN | 0/3 | ~0.45x | ✓ yes | Tunnel hides content, not timing |
| No VPN | 3/3 | ~1.1x | ✓ yes | DPI fully visible |
| VLESS Reality | 0/3 | 26–394x | ✗ no | Middlebox completely lost |

**Finding 6 - VLESS Reality defeats timing analysis**

AdGuard hides SNI drops but the middlebox RST ratio stays at ~0.45x, the interceptor still responds faster than the real server, revealing its presence through timing alone.

Under VLESS Reality the RST ratio explodes to 26x–394x baseline. The middlebox no longer knows what to intercept or how to respond. It does not just hide the content, it fundamentally changes the network behavior profile to the point where DPI fingerprinting produces no usable signal.

This is the difference between a VPN and a protocol designed to defeat deep inspection.

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

These six findings together confirm an active, sophisticated, and deliberately opaque DPI infrastructure that filters on SNI, correlates with destination IP reputation, suppresses ICMP to hide its presence, injects responses faster than the real destination, runs a full TLS parser, and can be partially bypassed by commercial VPNs; but not by VLESS Reality.

---

## Usage

```bash
# Auto-detect mode - no argument needed
py main.py

# Full probe against a specific target
py main.py <target_ip>
```

A JSON report is automatically saved to the current directory when probing a specific target.

---

## Stack

- Python 3.11+
- Raw sockets - no external dependencies

---

## Roadmap

### Phase 1 - Core probes
- [x] TCP 443 reachability test
- [x] Plain HTTP behavior test
- [x] SNI fingerprinting
- [x] TTL hop analysis
- [x] RST timing fingerprinting
- [x] Malformed TLS ClientHello probes
- [x] JSON report output

### Phase 2 - Reliability
- [x] Repeat each probe with configurable sample count
- [x] Report median, p95, timeout rate, and variance
- [ ] Add clean/blocked domain lists from config files
- [ ] Test multiple destination IPs in one run
- [ ] Separate raw observations from interpretations
- [ ] Replace single score with per-signal confidence levels

### Phase 3 - DPI classification
- [ ] Detect SNI-based filtering
- [ ] Detect IP-based blocking
- [ ] Detect HTTP Host header filtering
- [ ] Detect silent drops
- [ ] Detect RST injection
- [ ] Detect TLS parser interference
- [ ] Detect SNI + destination-IP correlation

### Phase 4 - Fingerprinting
- [ ] Capture response TTL where supported
- [ ] Compare suspicious response TTL vs baseline response TTL
- [ ] Map hop count vs RTT to estimate middlebox distance
- [ ] Add optional PCAP capture/export
- [ ] Fingerprint TLS alert behavior by malformed ClientHello variant
- [ ] Compare HTTP vs HTTPS behavior on the same target set

### Phase 5 - Usability
- [x] Auto-detect local DPI/interference profile
- [ ] Add CLI options for targets, ports, samples, timeouts, and config files
- [ ] Generate human-readable text report
- [ ] Generate machine-readable JSON report with stable schema
- [ ] Add `--quick`, `--full`, and `--stealth` modes

---

## Author

[allanjoshuaf](https://github.com/allanjoshuaf)