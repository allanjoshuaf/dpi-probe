# dpi-probe

`dpi-probe` collects repeatable evidence about content-dependent network
behavior and tunnel failures. It deliberately does **not** turn every timeout,
RST, DNS difference, or missing ICMP reply into a claim that a DPI was found.

The report keeps four things separate:

1. what was observed;
2. what the observation is compatible with;
3. what can be attributed to the path, destination, client, or server;
4. what evidence is still missing.

Status: public alpha. Use only on networks and endpoints you are authorized to
test.

The complete technical review is in [AUDIT_TECHNIQUE.md](AUDIT_TECHNIQUE.md),
and the command-by-command personal guide is in
[GUIDE_UTILISATEUR.md](GUIDE_UTILISATEUR.md).

## Install and verify

```powershell
py -m pip install -r requirements.txt
py -m pip install -r requirements-dev.txt
py -m pytest -q
py -m coverage run --source=src -m pytest -q
py -m coverage report --omit="src/probes/*"
py main.py --help
```

Python 3.11+ is required. PCAP analysis requires Wireshark/TShark. Live capture
on Windows also requires Npcap and appropriate privileges.

The test suite currently contains 38 tests and is also run on GitHub for Python
3.11 and 3.13. Field captures and session notes are deliberately ignored by
Git because they can contain endpoint addresses and browsing metadata.

```powershell
py -c "from src import pcap; [print(i) for i in pcap.list_interfaces()]"
```

## Measurement modes

```powershell
# Lightweight differential observation
py main.py

# Full probe against one measurement endpoint
py main.py 1.1.1.1 --samples 3 --profile direct

# Capture the full probe on a verified interface
py main.py 1.1.1.1 --samples 3 --pcap --pcap-interface 3

# Compare two reports, for example direct versus tunnel
py main.py --compare reports\direct.json reports\reality.json

# Inspect ECH advertisement and local runtime capability
py main.py --ech cloudflare-ech.com
```

The public IPs in `targets.json` are non-controlled anycast measurement
endpoints. They are not authoritative TLS/HTTP servers for every test name.
Consequently, an SNI- or Host-dependent difference is useful evidence but does
not by itself separate an on-path action from destination-side virtual-host
policy.

## Diagnose sing-box VLESS/REALITY

The tunnel diagnosis accepts any combination of a sing-box configuration,
timestamped log, client PCAP, local Clash API, and active endpoint checks.
Credentials are reduced to booleans/lengths and are not copied into the report.

```powershell
py main.py --diagnose-tunnel `
  --sing-box-config C:\path\config.json `
  --sing-box-log C:\path\box.log `
  --tunnel-pcap C:\path\client.pcapng `
  --tunnel-endpoint SERVER_IP:443
```

Optional endpoint checks:

```powershell
py main.py --diagnose-tunnel `
  --sing-box-config C:\path\config.json `
  --tunnel-endpoint SERVER_IP:443 `
  --active-tunnel-checks `
  --underlay-interface-index 18
```

Optional local Clash API snapshot (keep the API bound to loopback):

```powershell
$env:DPI_PROBE_CLASH_SECRET = "your-secret"
py main.py --diagnose-tunnel `
  --sing-box-api http://127.0.0.1:9090 `
  --sing-box-secret-env DPI_PROBE_CLASH_SECRET
```

The diagnosis labels per-stream phases such as:

- TCP handshake absent;
- TCP established but first client payload unanswered;
- bidirectional encrypted data established;
- established flow later retransmitting;
- client cleanup reset after unanswered data;
- apparent target-direction reset.
- late target-direction reset after an already orderly FIN/FIN close.

On Windows, `--underlay-interface-index` is important when a TUN owns the
default route. It binds endpoint TCP/TLS checks to the physical interface;
without it, the test can loop through the tunnel it is trying to measure.

This finds **when** a tunnel fails from one vantage. It does not find the exact
router.

## Locate direction and reset origin with two PCAPs

For useful attribution, capture the same failure window at both ends:

```powershell
# Client, use the correct interface number
tshark -i 3 -f "host SERVER_IP and tcp port 443" -w client.pcapng
```

```bash
# VPS/server
sudo tcpdump -i any -nn 'tcp port 443' -w server.pcap
```

Then compare absolute TCP sequence numbers:

```powershell
py main.py --dual-pcap client.pcapng server.pcap `
  --tunnel-endpoint SERVER_IP:443 `
  --flow-output reports\dual-vantage.json
```

Interpretation:

- client payload present only in the client capture: divergence on the forward
  path between the two capture points;
- server payload present only in the VPS capture: reverse-path divergence;
- server-to-client RST present only at the client: compatible with an injected
  or spoofed reset, but first exclude capture loss/offload;
- RST present at the VPS and client: visible at the server vantage, so it is not
  an event that appeared only near the client.

The exact physical hop still requires additional vantage points or a controlled
TTL-limited experiment. Traceroute alone cannot identify a silent packet drop.

## Reverse traceroute

A return path can only be measured from a cooperative remote host:

```powershell
py main.py --reverse-trace YOUR_PUBLIC_IP --reverse-agent user@YOUR_VPS
```

This describes the remote-agent-to-destination route. It does not make an
arbitrary public service trace back to you, and asymmetric paths are normal.
Never use a residential address as the destination. For an international path
comparison, deploy a second controlled VPS in a datacenter and trace only
between the two controlled hosts.

## What each legacy probe really measures

| Probe | Direct observation | Not proven by that observation |
|---|---|---|
| Crafted SNI | response/alert/EOF/timeout differs with ClientHello content | who made the decision |
| HTTP Host | response differs with a visible Host value | on-path filtering versus virtual-host policy |
| DNS | resolver answer sets differ | poisoning; CDNs and split DNS can differ normally |
| TTL samples | selected outgoing TTLs connect or do not connect | exact hop, ICMP suppression, DPI location |
| Plaintext on 443 | data, EOF, timeout, or a real socket reset after invalid protocol input | reset origin without PCAP |
| Malformed TLS | a parser returns an alert/data/reset or nothing | parser location from timing alone |
| TCP write segmentation | outcome changes with application write boundaries | guaranteed IP fragmentation |
| TLS record split/mutation | outcome changes after changing the ClientHello | a confirmed usable bypass |
| JA3/JA3S | fingerprint of this handcrafted hello and returned ServerHello | Chrome/Firefox identity or middlebox ownership |

## ECH scope

`--ech` reads the DNS HTTPS/SVCB record and reports whether an ECH configuration
is advertised. It only claims a handshake if the local TLS runtime actually
offers and completes ECH. ECH is standardized in RFC 9849 and bootstrapped with
DNS service bindings by RFC 9848.

## sing-box logging for a reproduction window

Official sing-box configuration supports timestamped file logging:

```json
{
  "log": {
    "disabled": false,
    "level": "debug",
    "output": "box.log",
    "timestamp": true
  }
}
```

Do not leave verbose logging enabled indefinitely. Logs and PCAPs can expose
destinations, timings, local/public addresses, routing policy, and usage
patterns.

## Known limits and next evidence needed

- A public endpoint is not a controlled responder. The strongest future test is
  a VPS service that logs received probe IDs and packets.
- A client-only PCAP cannot distinguish a server-side discard from a packet
  lost after leaving the client.
- Dual PCAP locates divergence between endpoints, not the exact router.
- NIC offload and capture loss must be considered before declaring injection.
- VLESS/REALITY encrypts inner destinations. Correlating a failure requires
  timestamped sing-box logs or API connection metadata.
- Default domain labels become stale; treat `clean` and `blocked` as hypotheses,
  not ground truth.

## Primary references

- [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [RFC 9848 — Bootstrapping ECH with DNS Service Bindings](https://www.rfc-editor.org/info/rfc9848/)
- [RFC 9505 — Survey of Worldwide Censorship Techniques](https://www.rfc-editor.org/info/rfc9505/)
- [sing-box VLESS outbound](https://sing-box.sagernet.org/configuration/outbound/vless/)
- [sing-box TLS/REALITY fields](https://sing-box.sagernet.org/configuration/shared/tls/)
- [sing-box logging](https://sing-box.sagernet.org/configuration/log/)
- [sing-box Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/)
- [XTLS REALITY implementation notes](https://github.com/XTLS/REALITY/blob/main/README.en.md)
