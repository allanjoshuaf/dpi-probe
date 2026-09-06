"""Diagnostics for sing-box VLESS/REALITY tunnel failures."""

from __future__ import annotations

import datetime
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any

from src import flow_analysis, tunnel_assessment


LOG_PATTERNS = {
    "dns_resolution": re.compile(r"(?i)(?=.*\b(dns|resolve)\b)(?=.*\b(fail|error|timeout|nxdomain)\b)|no such host"),
    "tcp_connect": re.compile(r"(?i)(?=.*\b(dial|connect)\w*\b)(?=.*\b(timeout|refused|unreachable|reset|failed|error)\b)|no route"),
    "reality_or_tls_handshake": re.compile(r"(?i)(?=.*\b(reality|tls|handshake|certificate|short.?id|public.?key)\b)(?=.*\b(fail\w*|error|timeout|invalid|reject\w*|eof)\b)"),
    "transport_closed": re.compile(r"(?i)(?=.*\b(connection|stream|transport)\b)(?=.*\b(closed|reset|broken|eof)\b)|broken pipe|unexpected eof"),
    "routing": re.compile(r"(?i)(?=.*\b(route|routing|outbound|detour)\b)(?=.*\b(fail\w*|error|not found|unavailable)\b)"),
    "clock_skew": re.compile(r"(?i)(?=.*\b(time|clock|timestamp)\b)(?=.*\b(invalid|exceed\w*|skew|difference)\b)"),
}

SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(uuid|password|passwd|token|secret|private[_ -]?key|public[_ -]?key|short[_ -]?id|sid|pbk)\b"
    r"([\"']?\s*[:=]\s*|\s+)(?:\"[^\"]*\"|'[^']*'|[^\s,;\]\}&]+)"
)
UUID_VALUE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")


def _redact_log_line(text: str) -> str:
    """Remove common credentials before excerpts enter a JSON report."""
    text = UUID_VALUE.sub("<redacted-uuid>", text)
    text = re.sub(r"(?i)\bvless://\S+", "<redacted-vless-uri>", text)
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", text)
    return SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", text)


def _history_last_delay(row: dict[str, Any]) -> Any:
    history = row.get("history")
    if not isinstance(history, list) or not history or not isinstance(history[-1], dict):
        return None
    return history[-1].get("delay")


def _load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("sing-box config must contain a JSON object")
    return data


def inspect_sing_box_config(path: str) -> dict[str, Any]:
    """Extract non-secret VLESS/REALITY settings and flag diagnostic gaps."""
    config = _load_json(path)
    outbounds = config.get("outbounds") or []
    if not isinstance(outbounds, list):
        raise ValueError("sing-box outbounds must be an array")
    inspected = []
    for index, outbound in enumerate(outbounds):
        if not isinstance(outbound, dict) or outbound.get("type") != "vless":
            continue
        tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
        reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
        utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
        short_id = reality.get("short_id")
        issues = []
        if not outbound.get("server") or not outbound.get("server_port"):
            issues.append("missing_server_or_port")
        elif (not isinstance(outbound["server"], str) or isinstance(outbound["server_port"], bool)
              or not isinstance(outbound["server_port"], int) or not 1 <= outbound["server_port"] <= 65535):
            issues.append("invalid_server_or_port")
        if not outbound.get("uuid"):
            issues.append("missing_uuid")
        if outbound.get("flow") not in (None, "", "xtls-rprx-vision"):
            issues.append("unsupported_vless_flow")
        if reality.get("enabled"):
            if not tls.get("enabled"):
                issues.append("reality_requires_tls_enabled")
            if not reality.get("public_key"):
                issues.append("reality_public_key_missing")
            if short_id is not None and (not isinstance(short_id, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id)):
                issues.append("reality_short_id_must_be_0_to_8_bytes_hex")
            if not tls.get("server_name"):
                issues.append("reality_server_name_missing")
        if tls.get("insecure"):
            issues.append("tls_certificate_verification_disabled")
        if utls.get("enabled"):
            issues.append("utls_enabled_official_sing_box_docs_do_not_recommend_it")

        inspected.append({
            "index": index,
            "tag": outbound.get("tag"),
            "type": "vless",
            "server": outbound.get("server"),
            "server_port": outbound.get("server_port"),
            "uuid_present": bool(outbound.get("uuid")),
            "flow": outbound.get("flow"),
            "network": outbound.get("network", "tcp+udp"),
            "transport_type": (outbound.get("transport") or {}).get("type") if isinstance(outbound.get("transport"), dict) else None,
            "multiplex_enabled": bool((outbound.get("multiplex") or {}).get("enabled")) if isinstance(outbound.get("multiplex"), dict) else False,
            "tls_enabled": bool(tls.get("enabled")),
            "server_name": tls.get("server_name"),
            "handshake_timeout": tls.get("handshake_timeout"),
            "reality_enabled": bool(reality.get("enabled")),
            "reality_public_key_present": bool(reality.get("public_key")),
            "reality_short_id_length_bytes": len(short_id) // 2 if isinstance(short_id, str) else None,
            "utls_enabled": bool(utls.get("enabled")),
            "utls_fingerprint": utls.get("fingerprint") if utls.get("enabled") else None,
            "issues": issues,
        })

    log_config = config.get("log") if isinstance(config.get("log"), dict) else {}
    return {
        "path": os.path.abspath(path),
        "vless_outbounds": inspected,
        "logging": {
            "disabled": bool(log_config.get("disabled")),
            "level": log_config.get("level", "info"),
            "output": log_config.get("output"),
            "timestamp": bool(log_config.get("timestamp")),
        },
        "recommendations": [
            "Use timestamped debug logs only during a reproduction window; trace logs may contain sensitive destinations.",
            "Enable experimental.clash_api on 127.0.0.1 with a secret if live connection counters are needed.",
        ],
    }


def analyze_log(path: str, max_events: int = 200) -> dict[str, Any]:
    counts = {category: 0 for category in LOG_PATTERNS}
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            text = line.strip()
            for category, pattern in LOG_PATTERNS.items():
                if pattern.search(text):
                    counts[category] += 1
                    if len(events) < max_events:
                        events.append({
                            "line": line_number,
                            "category": category,
                            "text": _redact_log_line(text)[:500],
                        })
                    break
    dominant = max(counts, key=counts.get) if any(counts.values()) else None
    return {
        "path": os.path.abspath(path),
        "category_counts": counts,
        "dominant_failure_stage": dominant,
        "events": events,
        "limitations": [
            "Log classification is based on message text and must be checked against the original surrounding lines.",
            "Application logs identify the software stage, not the physical network hop.",
        ],
    }


def _connect_with_optional_windows_interface(
    host: str,
    port: int,
    timeout: float,
    interface_index: int | None,
) -> socket.socket:
    if interface_index is None:
        return socket.create_connection((host, port), timeout=timeout)
    if interface_index < 1:
        raise ValueError("underlay interface index must be positive")
    if platform.system().lower() != "windows":
        raise ValueError("--underlay-interface-index is currently supported on Windows only")

    ipv4_addresses = [
        row[4][0]
        for row in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    ]
    if not ipv4_addresses:
        raise ValueError("underlay interface selection currently requires an IPv4 endpoint")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows IP_UNICAST_IF. Python does not expose the constant, but Winsock
    # defines it as 31 and expects the interface index in network byte order.
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(interface_index))
        sock.connect((ipv4_addresses[0], port))
    except Exception:
        sock.close()
        raise
    return sock


def tcp_connect_samples(
    host: str,
    port: int,
    samples: int = 3,
    timeout: float = 4.0,
    interface_index: int | None = None,
) -> dict[str, Any]:
    try:
        addresses = flow_analysis.resolve_endpoint(host, port)
    except socket.gaierror as exc:
        return {"host": host, "port": port, "attempts": [], "resolution_error": str(exc)}
    attempts = []
    for _ in range(samples):
        started = time.monotonic()
        try:
            with _connect_with_optional_windows_interface(
                host, port, timeout, interface_index
            ) as sock:
                local = sock.getsockname()
                remote = sock.getpeername()
            attempts.append({
                "status": "connected",
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "local_address": local[0],
                "remote_address": remote[0],
            })
        except OSError as exc:
            attempts.append({
                "status": "error",
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "error_type": type(exc).__name__,
                "errno": exc.errno,
                "error": str(exc),
            })
        time.sleep(0.1)
    return {
        "host": host,
        "port": port,
        "resolved_addresses": addresses,
        "interface_index": interface_index,
        "path_scope": (
            f"windows_underlay_interface_{interface_index}"
            if interface_index is not None else "system_default_route"
        ),
        "attempts": attempts,
    }


def tls_cover_check(
    host: str,
    port: int,
    server_name: str,
    timeout: float = 8.0,
    interface_index: int | None = None,
) -> dict[str, Any]:
    """Verify the ordinary TLS certificate presented for the REALITY cover SNI."""
    started = time.monotonic()
    raw = None
    try:
        context = ssl.create_default_context()
        raw = _connect_with_optional_windows_interface(
            host, port, timeout, interface_index
        )
        tcp_ms = (time.monotonic() - started) * 1000
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            certificate = tls.getpeercert()
            subject = dict(item[0] for item in certificate.get("subject", ()))
            issuer = dict(item[0] for item in certificate.get("issuer", ()))
            return {
                "status": "verified",
                "server_name": server_name,
                "tcp_ms": round(tcp_ms, 2),
                "tls_total_ms": round((time.monotonic() - started) * 1000, 2),
                "tls_version": tls.version(),
                "cipher": tls.cipher()[0],
                "certificate_common_name": subject.get("commonName"),
                "issuer_organization": issuer.get("organizationName"),
                "subject_alt_name_count": len(certificate.get("subjectAltName", ())),
                "interface_index": interface_index,
            }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {
            "status": "error",
            "server_name": server_name,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "interface_index": interface_index,
        }
    finally:
        if raw is not None:
            raw.close()


def route_snapshot(host: str) -> dict[str, Any]:
    system = platform.system().lower()
    if system == "windows":
        command = ["tracert", "-d", "-h", "30", "-w", "1000", host]
    else:
        command = ["traceroute", "-n", "-m", "30", "-w", "1", host]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
        return {
            "command": command,
            "status": "ok" if completed.returncode == 0 else "partial",
            "returncode": completed.returncode,
            "output": completed.stdout.strip(),
            "error": completed.stderr.strip() or None,
            "scope": "system_default_route",
            "warning": "With an active TUN default route, this traceroute can describe the tunnel rather than the physical underlay.",
        }
    except FileNotFoundError:
        return {"command": command, "status": "tool_not_found"}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {"command": command, "status": "timeout", "output": output[-10000:]}


def clash_api_snapshot(base_url: str, secret: str | None = None) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(base_url)
    if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Clash API must be a loopback HTTP(S) URL without credentials or query")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    base = base_url.rstrip("/")
    result = {"base_url": base, "endpoints": {}, "secret_recorded": False}
    for endpoint in ("/version", "/connections", "/proxies"):
        request = urllib.request.Request(base + endpoint)
        if secret:
            request.add_header("Authorization", f"Bearer {secret}")
        try:
            with opener.open(request, timeout=4) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if endpoint == "/connections" and isinstance(payload, dict):
                connections = payload.get("connections") or []
                payload = {
                    "downloadTotal": payload.get("downloadTotal"),
                    "uploadTotal": payload.get("uploadTotal"),
                    "active_connection_count": len(connections),
                    "connections": [
                        {
                            "id": row.get("id"),
                            "upload": row.get("upload"),
                            "download": row.get("download"),
                            "start": row.get("start"),
                            "chains": row.get("chains"),
                            "rule": row.get("rule"),
                            "network": (row.get("metadata") or {}).get("network"),
                            "type": (row.get("metadata") or {}).get("type"),
                        }
                        for row in connections[:100] if isinstance(row, dict)
                    ],
                }
            elif endpoint == "/proxies" and isinstance(payload, dict):
                proxies = payload.get("proxies") or {}
                payload = {
                    "proxy_count": len(proxies),
                    "proxies": {
                        name: {
                            "type": row.get("type"),
                            "udp": row.get("udp"),
                            "alive": row.get("alive"),
                            "history_last_delay": _history_last_delay(row),
                        }
                        for name, row in list(proxies.items())[:200]
                        if isinstance(row, dict)
                    },
                }
            result["endpoints"][endpoint] = {"status": "ok", "data": payload}
        except (urllib.error.URLError, TimeoutError, ValueError, TypeError, AttributeError) as exc:
            result["endpoints"][endpoint] = {"status": "error", "error": str(exc)}
    return result


def _select_endpoint(config_analysis: dict[str, Any] | None, explicit_endpoint: str | None) -> str | None:
    if explicit_endpoint:
        return explicit_endpoint
    outbounds = (config_analysis or {}).get("vless_outbounds") or []
    if len(outbounds) == 1 and outbounds[0].get("server") and outbounds[0].get("server_port"):
        host = outbounds[0]["server"]
        if ":" in str(host) and not str(host).startswith("["):
            host = f"[{host}]"
        return f"{host}:{outbounds[0]['server_port']}"
    return None


def run(
    endpoint: str | None = None,
    config_path: str | None = None,
    log_path: str | None = None,
    pcap_path: str | None = None,
    clash_api: str | None = None,
    clash_secret: str | None = None,
    active_checks: bool = False,
    underlay_interface_index: int | None = None,
    output_path: str | None = None,
    server_pcap_path: str | None = None,
    outbound_tag: str | None = None,
    samples: int = 3,
) -> dict[str, Any]:
    if not any((config_path, log_path, pcap_path, clash_api, active_checks)):
        raise ValueError("provide a config, log, capture, local API or --active-tunnel-checks")
    if server_pcap_path and not pcap_path:
        raise ValueError("--server-pcap requires --tunnel-pcap")
    if samples < 1:
        raise ValueError("samples must be positive")
    if underlay_interface_index is not None and (underlay_interface_index < 1 or platform.system().lower() != "windows"):
        raise ValueError("underlay interface index must be positive and requires Windows")
    config_analysis = inspect_sing_box_config(config_path) if config_path else None
    if outbound_tag:
        rows = [row for row in (config_analysis or {}).get("vless_outbounds", []) if row.get("tag") == outbound_tag]
        if len(rows) != 1:
            raise ValueError("--outbound-tag must match exactly one VLESS outbound in --sing-box-config")
        config_analysis["vless_outbounds"] = rows
    selected_endpoint = _select_endpoint(config_analysis, endpoint)
    if selected_endpoint:
        flow_analysis.parse_endpoint(selected_endpoint)
    report: dict[str, Any] = {
        "schema_version": "1.1",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": {"platform": platform.platform(), "python": platform.python_version()},
        "endpoint": selected_endpoint,
        "config": config_analysis,
        "log": analyze_log(log_path) if log_path else None,
        "pcap": None,
        "dual_pcap": None,
        "clash_api": clash_api_snapshot(clash_api, clash_secret) if clash_api else None,
        "active_checks": None,
        "data_needed_for_localization": [],
    }
    if pcap_path:
        if not selected_endpoint:
            raise ValueError("--tunnel-pcap requires --tunnel-endpoint or one unambiguous VLESS outbound in the config")
        report["pcap"] = flow_analysis.analyze_single_pcap(pcap_path, selected_endpoint)
    if server_pcap_path:
        report["dual_pcap"] = flow_analysis.compare_vantages(pcap_path, server_pcap_path, selected_endpoint)
    if active_checks:
        if not selected_endpoint:
            raise ValueError("active checks require a tunnel endpoint")
        host, port = flow_analysis.parse_endpoint(selected_endpoint)
        vless_rows = (config_analysis or {}).get("vless_outbounds") or []
        matching = [row for row in vless_rows if (str(row.get("server")), row.get("server_port")) == (host, port)]
        # Explicit endpoint overrides must not accidentally use another server's SNI.
        cover_names = {row["server_name"] for row in matching if row.get("server_name")}
        cover_name = next(iter(cover_names)) if len(cover_names) == 1 else None
        report["active_checks"] = {
            "tcp": tcp_connect_samples(
                host, port, samples=samples, interface_index=underlay_interface_index
            ),
            "route": route_snapshot(host),
            "tls_cover": (
                tls_cover_check(
                    host,
                    port,
                    cover_name,
                    interface_index=underlay_interface_index,
                )
                if cover_name else None
            ),
        }

    if not log_path:
        report["data_needed_for_localization"].append("timestamped sing-box debug log covering the failure window")
    if not pcap_path:
        report["data_needed_for_localization"].append("client PCAP filtered to the REALITY server endpoint and port")
    if not server_pcap_path:
        report["data_needed_for_localization"].append(
            "server-side PCAP for the same window; pass --server-pcap alongside --tunnel-pcap"
        )
    report["diagnosis"] = tunnel_assessment.assess(report)

    if not output_path:
        Path("reports").mkdir(exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"reports/tunnel_diagnosis_{timestamp}.json"
    flow_analysis.save_analysis(report, output_path)
    markdown_path = str(Path(output_path).with_suffix(".md"))
    if markdown_path == str(output_path):
        markdown_path += ".md"
    Path(markdown_path).write_text(tunnel_assessment.render_markdown(report), encoding="utf-8")

    print("\n[*] sing-box / VLESS REALITY diagnosis")
    print(f"    Endpoint       : {selected_endpoint or 'not determined'}")
    if report["pcap"]:
        phases = {}
        for stream in report["pcap"]["streams"]:
            phases[stream["phase"]] = phases.get(stream["phase"], 0) + 1
        print(f"    PCAP phases     : {phases}")
    if report["log"]:
        print(f"    Log stage       : {report['log']['dominant_failure_stage'] or 'no known failure pattern'}")
    print(f"    Report          : {output_path}")
    print(f"    Readable report : {markdown_path}")
    for finding in report["diagnosis"]["findings"]:
        print(f"    [{finding['confidence']}] {finding['stage']}: {finding['location']}")
    return report
