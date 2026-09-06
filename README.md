# dpi-probe

[English](README.md) | [Français](README.fr.md) | [Русский](README.ru.md) | [简体中文](README.zh.md)

**1.0.0-beta.1** is a terminal toolkit for investigating network interference: DNS anomalies, TCP failures, TLS/SNI and HTTP Host differences, ECH availability, resets, segmentation and path differences. VLESS/REALITY diagnosis is one specialized module.

dpi-probe collects observations, compares conditions and suggests what evidence to collect next. A timeout does not prove censorship. A reset does not identify its author. Two packet captures can bound a discrepancy between observation points, not identify an exact filtering router.

## When it helps

| Situation | Evidence and practical use |
|---|---|
| A service works on mobile but fails on home broadband | Compare reports using the same target and parameters; separate DNS, connection and TLS differences. |
| Suspected DNS poisoning | Compare local and reference answers. CDN variation and failed reference resolvers remain alternative explanations. |
| TCP connects but TLS stalls | Vary SNI, TLS fields and TCP write segmentation; inspect whether client data receives an answer. |
| Is ECH actually usable? | Separate HTTPS DNS publication from an optional request that requires ECH using a compatible curl. |
| Resets, stalls or asymmetric delivery | Inspect client/server captures, sequence ranges, acknowledgments and FIN/RST order. |
| A VLESS/REALITY connection fails | Inspect sing-box configuration, logs, endpoint, route and captures; report the observed phase, possible causes and next checks. |

## Install and launch

Download and extract the repository, then open its directory. On Windows, double-click **`dpi-probe.cmd`**. On Linux, run **`sh dpi-probe.sh`** in a terminal.

The launcher checks Python 3.11+, offers to create `.venv` and install `requirements.txt`, then checks TShark and capture interfaces. Installation requires your answer to each prompt. Windows offers Python 3.13 and Wireshark through winget; finish the interactive installer, including TShark and Npcap. If winget is unavailable, install Python from its official site and relaunch. Debian/Ubuntu use apt where supported. Other distributions receive manual instructions. Installing packages can require administrator privileges.

The Python dependencies are `cryptography` and `dnspython`. Missing or incompatible required modules stop execution. Declining optional capture tools still permits probes that do not use captures; requesting a capture without working tools fails explicitly. A missing dependency is never evidence of filtering. The Wireshark GUI is useful for inspection, but TShark is the command-line dependency.

| Capability | Requirements |
|---|---|
| Core probes, menus and reports | Python 3.11+, venv/pip, requirements.txt |
| PCAP analysis | TShark |
| Live capture | TShark, Npcap on Windows or libpcap on Unix, capture permissions |
| Active ECH | A curl build supporting `--ech hard`; ordinary curl availability is insufficient |
| Remote reverse trace | SSH client and a controlled remote host with traceroute/tracert |

Manual setup on Windows:

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python main.py --doctor
.venv\Scripts\python main.py
```

On Linux, create the environment with `python3 -m venv .venv`, then substitute `.venv/bin/python` for `.venv\Scripts\python`. Install your distribution's venv/pip package if environment creation fails. `--doctor` checks local modules, TShark, interfaces, curl and SSH without sending probes; exit code 2 means core or capture prerequisites are missing. Interface enumeration does not guarantee permission to capture.

Windows is locally tested. Linux has automated CI coverage; physical Linux/OpenWrt field validation remains outstanding. On OpenWrt, prefer a short `tcpdump` capture on the router and analysis on a workstation. Installing the entire Python stack on a router is experimental and depends on storage, packages and architecture. The launcher does not modify routes or firewalls.

## Guided menu

Choose English, French, Russian or simplified Chinese at first launch. Option 6 changes the language later. Only the language code is stored in the user's configuration directory. Menus and input prompts are translated; technical output and reports are not fully localized. Installation prompts currently use English/French.

1. General diagnosis: quick, full or individual tests, with optional capture for the full run.
2. VLESS/REALITY diagnosis from configuration, logs and captures.
3. Advanced tools: two captures, passive/active ECH, capture interface list.
4. Compare two detailed reports.
5. Create a reduced report for voluntary sharing.
6. Change language. Use 0 to exit.

The full battery covers TCP/443, HTTP, SNI, TTL, RST, malformed TLS, destination differences, HTTP Host, DNS, TCP write segmentation, alternative TLS layouts, crafted TLS fingerprints, TLS mutations and passive ECH checks. Some historical module names contain “bypass” or “fragmentation”: their results describe changed responses, not a validated application bypass or IP fragmentation. Full runs can take several minutes. `--samples` repeats sampling-aware probes, not every operation.

## Scripted use

Run these commands with the environment's Python. No arguments opens the menu and requires an interactive terminal; `--auto` explicitly selects the quick automatic mode.

```text
python main.py --help
python main.py --version
python main.py --auto
python main.py 1.1.1.1 --samples 3 --profile direct
python main.py 1.1.1.1 --samples 3 --profile alternate --pcap --pcap-interface 3
python main.py --multi --samples 3
python main.py --compare reports/direct.json reports/alternate.json
python main.py --ech example.com
python main.py --ech example.com --ech-active
python main.py --anonymize reports/direct.json
```

Replace interface 3 with an interface listed by the advanced menu. Full-run capture filters the target's port 443; it does not capture every DNS request or other destination tested. `targets.json` configures IPv4 targets and domain groups. Its public anycast defaults are uncontrolled comparison endpoints, not authoritative TLS servers for every SNI. The historical `blocked`/`clean` labels express test groups, not established censorship classifications. Prefer controlled endpoints for attribution and run active tests only where you have permission.

Active ECH uses curl with `--ech hard`, Cloudflare DoH, certificate verification and no environment HTTP proxy. It distinguishes success, unsupported builds, ECH requirement failure and unresolved transport errors. TUN routing still applies. DNS publication alone does not prove ECH acceptance, and an ECH failure alone does not prove interference.

### Tunnel diagnosis and paired captures

```text
python main.py --diagnose-tunnel --sing-box-config config.json --outbound-tag reality --sing-box-log client.log --tunnel-endpoint SERVER_IP:443 --tunnel-pcap client.pcapng --server-pcap server.pcapng --diagnosis-output reports/incident.json
python main.py --dual-pcap client.pcapng server.pcapng --tunnel-endpoint SERVER_IP:443 --flow-output reports/paired.json
```

Replace placeholders and omit optional files you do not have. The selected outbound must have a unique tag. For historical captures, supply the actual server IP used during that attempt, not a hostname that may now resolve differently. Capture the same reproduction window at both ends, with clocks synchronized. For example:

```text
tshark -D
tshark -i 3 -f "host SERVER_IP and tcp port 443" -a duration:30 -w client.pcapng
tcpdump -i any -s 0 -w server.pcap 'tcp port 443'
```

The guided tunnel capture asks you to reproduce the connection with your existing client. dpi-probe does not implement an authenticated REALITY client. Ordinary TLS success may be a fallback response and does not establish REALITY authentication.

Add `--active-tunnel-checks` for endpoint TCP/traceroute checks. Windows `--underlay-interface-index N` selects the physical interface for the endpoint TCP check; its Windows index is different from the TShark capture number. A route snapshot does not prove every probe bypasses a TUN. For local connection metadata, use `--sing-box-api http://127.0.0.1:9090` and `--sing-box-secret-env VARIABLE_NAME`; remote API URLs and redirects are rejected.

Reverse trace requires your own reachable remote agent:

```text
python main.py --reverse-trace PUBLIC_IP --reverse-agent probe@CONTROLLED_HOST
```

## Read and share results

Detailed general and tunnel reports include JSON and Markdown. Separate quick, ECH and paired-capture outputs have their own formats; the detailed comparator does not accept all of them. Reports remain under `reports/` unless an explicit output path is supplied. There is no automatic upload or continuous monitoring.

Observations, hypotheses and missing data are separate. NAT, asymmetric paths, offload, incomplete captures and capture loss can change the interpretation. Paired analysis matches TCP signatures and byte ranges, not authenticated payload content; missing ranges are not a measured network loss rate.

Raw captures, configurations and logs can expose addresses, domains and credentials. Common log secrets are redacted, but this is not a universal sanitizer. The reduced tunnel export retains diagnostic codes; the general export still retains tested domain names. Review any export before sharing. Reports, logs, packet captures and environments are ignored by Git.

## Validation and status

```text
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m coverage run --source=src -m pytest -q
python -m coverage report --omit="src/probes/*" --fail-under=40
python -m compileall -q main.py bootstrap.py src
python main.py --help
git diff --check
```

Tests cover report schemas, diagnostic regressions, menus/languages and synthetic captures passed through real TShark when available. Missing optional integration tools produce an explicit skip. They do not establish accuracy on every ISP. This is a beta pending controlled field validation, broader platform installation checks and native-language review.

See [technical audit](AUDIT_TECHNIQUE.md), [changes](CHANGELOG.md), [research roadmap](ROADMAP_RECHERCHE.md) and [MIT license](LICENSE). Installation references: [Python](https://www.python.org/downloads/), [Wireshark on Windows](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html), [curl ECH options](https://curl.se/docs/manpage.html#--ech).
