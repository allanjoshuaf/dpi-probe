# dpi-probe

`dpi-probe` is a Python tool for detecting and fingerprinting traffic interference on the local network path.

It probes whether TLS SNI, destination IP, HTTP Host headers, malformed TLS payloads, TTL behavior, or TCP reset timing are being filtered, dropped, injected, or modified by a DPI/middlebox.

> Status: public alpha. Results should be interpreted as network evidence, not forensic proof without packet captures.

---

## What It Tests

- TCP reachability on port 443
- Plain HTTP behavior on port 80
- TLS SNI filtering using crafted ClientHello packets
- Clean vs blocked domain differential behavior
- TTL hop behavior and ICMP suppression patterns
- RST/response timing compared to baseline RTT
- Malformed TLS ClientHello responses
- Repeated samples with median, p95, variance, and consistency rates
- JSON report with per-signal confidence levels

---

## Usage

```bash
# Auto-detect local traffic interference
py main.py

# Probe a specific target
py main.py 1.1.1.1

# Repeat each probe 3 times
py main.py 1.1.1.1 --samples 3

# Probe all configured targets from targets.json
py main.py --multi

# Probe all configured targets with repeated samples
py main.py --multi --samples 3
```

Targeted probes save JSON reports in the current directory.

---

## Configuration

Targets and domain lists are loaded from `targets.json`.

```json
{
  "targets": [
    {"ip": "1.1.1.1", "name": "Cloudflare DNS"},
    {"ip": "8.8.8.8", "name": "Google DNS"},
    {"ip": "9.9.9.9", "name": "Quad9 DNS"}
  ],
  "domains": {
    "blocked": ["instagram.com", "facebook.com", "twitter.com", "youtube.com", "x.com"],
    "clean": ["google.com", "github.com", "cloudflare.com", "yandex.ru", "rutube.ru"]
  }
}
```

---

## Example Output

```
==================================================
DPI PROBE REPORT
Target     : 1.1.1.1
Timestamp  : 2026-05-23T12:21:58Z
DPI detected  : YES
Confidence    : HIGH
Score         : 9/10
Findings :
→ SNI filtering observed for: instagram.com, facebook.com, twitter.com, x.com
→ TTL/ICMP behavior consistent with suppression at hops [1, 2, 3, 5, 8]
→ RST timing consistent with closer responder - 0.46x baseline
→ Malformed TLS responses faster than clean SNI baseline - timing consistent with middlebox TLS parser
```
The score is conservative by design. Each signal is weighted separately and reported with its own confidence level.

---

## Field Results: Russia

These are real observations from one Russian network path, included as field evidence. Results are network-path-specific and should not be generalized across ISPs or countries.

### SNI Filtering

Tested against `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google DNS), no VPN:

| SNI | 1.1.1.1 | 8.8.8.8 | Observed |
|---|---|---|---|
| google.com | tls_alert | tls_alert | PASS |
| github.com | tls_alert | tls_alert | PASS |
| cloudflare.com | tls_alert | tls_alert | PASS |
| yandex.ru | tls_alert | tls_alert | PASS |
| rutube.ru | tls_alert | tls_alert | PASS |
| instagram.com | silent_drop | silent_drop | BLOCKED |
| facebook.com | silent_drop | silent_drop | BLOCKED |
| twitter.com | silent_drop | silent_drop | BLOCKED |
| x.com | silent_drop | silent_drop | BLOCKED |
| youtube.com | tls_alert | silent_drop | PARTIAL |

SNI filtering observed on blocked domains. Clean domains pass consistently. `youtube.com` behavior differs between destinations, suggesting SNI + destination IP correlation.

### TTL Hop Analysis

| TTL | 1.1.1.1 | 8.8.8.8 |
|---|---|---|
| 1–8 | timeout | timeout |
| 13 | connected | timeout |
| 21 | connected | connected |
| 64 | connected | connected |

No ICMP TTL Exceeded responses observed between hop 1 and hop 13. This is consistent with ICMP suppression on the network path, though it is not conclusive on its own.

### RST Timing

| Target | Baseline RTT | RST Timing | Ratio | Observation |
|---|---|---|---|---|
| 1.1.1.1 | ~21ms | ~9ms | 0.46x | consistent with closer responder |
| 8.8.8.8 | ~22ms | ~24ms | 1.09x | no anomaly |

### Malformed TLS ClientHello

| Variant | Response | Alert Code | Median RTT |
|---|---|---|---|
| wrong_version | tls_alert | 0x28 | 13ms |
| empty_ciphers | tls_alert | 0x32 | 9ms |
| oversized_sni | tls_alert | 0x32 | 8ms |
| truncated | tls_alert | 0x32 | 7ms |
| duplicate_sni | tls_alert | 0x32 | 9ms |

Responses arrived faster than the clean SNI baseline on this network path, consistent with an intermediate TLS parser.

### VPN Comparison

| Condition | SNI drops | RST ratio | DPI signal | Note |
|---|---|---|---|---|
| No VPN | 4/5 | 0.46x | yes | filtering and timing anomaly observed |
| AdGuard VPN | 0/5 | ~0.45x | yes | SNI hidden, timing anomaly still present |
| VLESS Reality | 0/5 | 26–394x | no | no observable signal |

AdGuard masks SNI drops but the timing anomaly persists. In this test environment, VLESS Reality removed the observable DPI signals detected by the probe.

---

## Methodology

`dpi-probe` separates raw observations from interpretation.

- `silent_drop` on blocked SNI with clean domains responding suggests SNI-based filtering.
- RST/response timing significantly below baseline RTT may suggest a closer responder on the path.
- Missing ICMP TTL Exceeded responses are treated as a weak signal alone, stronger in combination.
- Malformed TLS responses are compared against clean SNI baseline timing before scoring.
- Each signal is reported with its own confidence level. The overall score aggregates independently weighted signals.

---

## Limitations

- No automatic PCAP capture yet. Run alongside Wireshark or `tcpdump` for stronger evidence.
- Response TTL is not captured yet. TTL-based attribution would significantly strengthen timing signals.
- Crafted ClientHello packets are realistic but not identical to Chrome/Firefox fingerprints.
- TTL timeouts alone do not prove DPI.
- Timing-based attribution is probabilistic without packet-level validation.
- Domain blocklists change over time and should be updated in `targets.json`.

---

## Safety

This tool generates traffic to domains that may be blocked or sensitive in some countries or networks.

Use it only where you understand the legal, operational, and personal risk.

Reports and packet captures may expose your IP address, ISP, tested domains, timestamps, and network behavior. Review them before sharing publicly.

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
- [x] Configurable sample count
- [x] Median, p95, variance, timeout rate
- [x] Config-based clean/blocked domain lists
- [x] Per-signal confidence levels
- [x] Separate observations from interpretations
- [ ] Multi-target probe in one run
- [ ] Stable JSON schema

### Phase 3 - DPI Classification
- [ ] IP-based blocking classification
- [ ] HTTP Host header filtering detection
- [ ] SNI + destination IP correlation detection

### Phase 4 - Fingerprinting
- [ ] Capture response TTL
- [ ] Compare response TTL vs baseline TTL
- [ ] Optional PCAP export
- [ ] Wireshark/tshark analysis helper
- [ ] Hop count vs RTT mapping

### Phase 5 - Usability
- [ ] `--quick`, `--full`, `--stealth` modes
- [ ] Human-readable text report
- [ ] Stable JSON schema with versioning
- [ ] PyPI package

---

## Stack

- Python 3.11+
- Standard library only - no external dependencies
- Standard-library TCP sockets, crafted TLS payloads

---

## Author

Built by [allanjoshuaf](https://github.com/allanjoshuaf)