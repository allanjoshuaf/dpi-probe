# dpi-probe

A tool to detect and fingerprint DPI (Deep Packet Inspection) middleboxes by analyzing TLS/SNI behavior across different network targets.

Built and tested from Russia 🇷🇺 — where DPI is part of daily life.

---

## What it does

- Tests TCP RST behavior on port 443
- Sends plain HTTP requests and checks for injection or redirect
- Crafts realistic TLS ClientHello packets with specific SNI values
- Compares server responses to detect silent drops, TLS alerts, and middlebox interference

---

## Real results — Russia, no VPN

Tested against `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google DNS):

| SNI | 1.1.1.1 | 8.8.8.8 |
|---|---|---|
| google.com | tls_alert | tls_alert |
| github.com | tls_alert | tls_alert |
| cloudflare.com | tls_alert | tls_alert |
| instagram.com | silent_drop | silent_drop |
| facebook.com | silent_drop | silent_drop |
| twitter.com | silent_drop | silent_drop |
| youtube.com | **tls_alert** | silent_drop |

### Key finding

The Russian DPI performs **SNI + destination IP correlation**.

`youtube.com` is blocked when sent to `8.8.8.8` (Google) but passes through to `1.1.1.1` (Cloudflare) — likely because Cloudflare serves thousands of legitimate Russian services, making blanket blocking too costly.

This confirms the DPI is not filtering on SNI alone — it weighs the destination IP reputation alongside the SNI value.

This is exactly the attack surface that **VLESS + Reality** bypasses: by borrowing a legitimate TLS identity, the SNI becomes meaningless to the inspector.

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

- [ ] TTL-based middlebox detection
- [ ] TCP RST origin fingerprinting
- [ ] TLS ClientHello malformation test
- [ ] JSON report output
- [ ] Auto-detect local DPI presence

---

## Author

[allanjoshuaf](https://github.com/allanjoshuaf)