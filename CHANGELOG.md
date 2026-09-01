# Changelog

All notable changes to dpi-probe are documented here.

## [Unreleased]

### Added
- ECH publication test through HTTPS/SVCB DNS records and a local TLS-runtime capability verdict
- Cooperative reverse traceroute over SSH from a remote host controlled by the user
- French user guide covering every CLI input and configuration field
- Unit-test discovery configuration plus ECH and reverse-traceroute test coverage
- Evidence-oriented report schema 2.0 separating observation, inference, attribution, and limitations
- sing-box VLESS/REALITY config inspection with credential redaction
- sing-box log failure-stage classification and optional local Clash API snapshots
- Per-stream tunnel PCAP phase timelines
- Dual-vantage client/VPS PCAP comparison using absolute TCP sequence numbers
- A real JSON Schema 2020-12 contract with automated validation
- Outer-tunnel RTT, TLS handshake, TTL and directional TCP-loss metrics
- Windows physical-interface binding for endpoint and cover-TLS checks
- GitHub CI on Python 3.11 and 3.13
- Active probes moved from the misleading `src/tests` package to `src/probes`; unit tests now live in top-level `tests`
- Coverage reporting for the deterministic core, with field-only probes explicitly separated

### Fixed
- Declared the `cryptography` and `dnspython` runtime dependencies
- Generated a fresh X25519 key share per crafted ClientHello and removed import-time debug output
- Validated `targets.json` before issuing probe traffic
- Handled missing tshark cleanly and made its default capture interface explicit
- Corrected the package initializer filenames and report schema/version drift
- Stopped treating timeouts as proven silent drops and empty TCP reads as resets
- Removed unsupported claims of pure SNI filtering, DNS poisoning, exact TTL suppression, and confirmed JA3/bypass attribution
- Distinguished client cleanup resets from apparent target-direction resets
- Replaced fixed RST TTL/window heuristics with raw features and baseline-relative context
- Redacted credentials from sing-box log excerpts and summarized Clash proxy data
- Failed closed on invalid target configuration instead of silently probing defaults
- Stopped treating mid-capture payload as a failed TCP handshake or ACKed one-way data as unanswered
- Removed a redundant TShark TTL query and narrowed malformed-value exception handling
- Fixed comparison of a real zero RST ratio, which was previously treated as missing

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

The original 0.1 field interpretations are retracted. The captures came from
public, non-controlled anycast endpoints and cannot establish SNI filtering,
ICMP suppression, or the absence of DPI under VLESS/REALITY. The raw files can
still be re-analysed as transport observations with schema 2.0 and the tunnel
flow analyzer.
