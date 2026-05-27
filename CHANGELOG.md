# Changelog

All notable changes to dpi-probe are documented here.

## [0.1.0-alpha] - 2026-05-23

### Added
- TCP 443 reachability test
- Plain HTTP behavior test (port 80)
- TLS SNI fingerprinting via crafted ClientHello packets
- TTL hop analysis with ICMP suppression detection
- RST origin timing fingerprinting
- Malformed TLS ClientHello probes (5 variants)
- JSON report output with schema version
- Per-signal confidence levels (sni_filtering, ttl_suppression, rst_timing, tls_parser)
- Configurable sample count via `--samples N`
- Median, p95, variance, timeout rate per test
- External config via `targets.json` (clean/blocked domains, target IPs)
- Multi-target mode via `--multi`
- Auto-detection mode (no argument required)
- Safety section and limitations documented

### Field Results
- Tested from Russia across three conditions: no VPN, AdGuard VPN, VLESS Reality
- SNI filtering observed for instagram.com, facebook.com, twitter.com, x.com
- TTL/ICMP suppression consistent across all runs
- VLESS Reality removed all observable DPI signals