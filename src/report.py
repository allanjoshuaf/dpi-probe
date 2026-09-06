"""Build evidence-oriented reports without claiming more than the data shows."""

from __future__ import annotations

import datetime
import json
import os
import uuid
from pathlib import Path
from src.version import VERSION
from typing import Any


NO_RESPONSE_OUTCOMES = {
    "silent_drop",  # legacy reports
    "timeout",
    "no_response_before_timeout",
    "connection_closed_no_data",
    "eof",
}
RESPONSE_OUTCOMES = {"tls_alert", "server_hello", "ok", "response"}


def _rows(value: Any) -> list[dict[str, Any]]:
    """Return successful tabular probe output; ignore per-test error objects."""
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _mapping(value: Any) -> dict[str, Any]:
    """Return a mapping or an empty one for a failed/legacy probe result."""
    return value if isinstance(value, dict) else {}


def _signal(
    observation: str,
    inference: str,
    strength: str,
    attribution: str = "unresolved",
    limitations: list[str] | None = None,
    consistency: float | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "observation": observation,
        "inference": inference,
        "strength": strength,
        "attribution": attribution,
        "limitations": limitations or [],
    }
    if consistency is not None:
        item["consistency"] = round(consistency, 3)
    return item


def _sni_evidence(results: dict[str, Any]) -> dict[str, Any] | None:
    rows = _rows(results.get("sni"))
    if not rows:
        return None
    no_response = [r for r in rows if r.get("dominant_response") in NO_RESPONSE_OUTCOMES]
    responding_clean = [
        r for r in rows
        if r.get("category") == "clean" and r.get("dominant_response") in RESPONSE_OUTCOMES
    ]
    suspect_no_response = [r for r in no_response if r.get("category") == "blocked"]
    if not suspect_no_response or not responding_clean:
        return _signal(
            observation="The crafted TLS probes did not produce a usable clean-versus-suspect differential.",
            inference="No SNI-dependent path conclusion can be drawn from this run.",
            strength="inconclusive",
            limitations=["The destination is not a controlled TLS endpoint for every tested hostname."],
        )

    domains = [r.get("sni", "?") for r in suspect_no_response]
    consistency_values = []
    for row in suspect_no_response:
        breakdown = row.get("status_breakdown") or {}
        consistency_values.append(max(breakdown.values()) if breakdown else 0.0)
    consistency = min(consistency_values) if consistency_values else 0.0

    pcap_corr = _mapping(results.get("pcap_correlation"))
    retransmitted = [
        domain for domain in domains
        if (pcap_corr.get(domain) or {}).get("retransmissions", 0) > 0
        and (pcap_corr.get(domain) or {}).get("tls_alerts", 0) == 0
    ]
    strength = "strong" if retransmitted and consistency >= 0.8 else "moderate"
    return _signal(
        observation=(
            f"On the same destination IP, {len(domains)} suspect hostname(s) had no TLS response "
            f"while {len(responding_clean)} comparison hostname(s) received a TLS response: {', '.join(domains)}."
        ),
        inference=(
            "The outcome depends on visible ClientHello content. This is compatible with on-path "
            "SNI interference, but also with destination-side virtual-host policy."
        ),
        strength=strength,
        attribution="on-path_or_destination",
        limitations=[
            "The target IP is not a controlled server for every hostname.",
            "A timeout proves absence of a response before the deadline, not who discarded the packet.",
        ],
        consistency=consistency,
    )


def _collect_signals(results: dict[str, Any]) -> dict[str, Any]:
    signals: dict[str, Any] = {}
    sni = _sni_evidence(results)
    if sni:
        signals["tls_sni_differential"] = sni
    ech_rows = _rows(results.get('ech'))
    if ech_rows:
        signals['ech_publication'] = _signal(
            observation=f"ECH advertised for {sum(bool(row.get('ech_advertised')) for row in ech_rows)}/{len(ech_rows)} queried names; no ECH handshake executed by this module.",
            inference="DNS publication and local API availability do not establish that ECH works on this network.",
            strength='context', attribution='dns_and_local_runtime',
            limitations=['A real ECH-capable client and confirmation of server acceptance are needed to test the ECH handshake.'],
        )

    ttl_analysis = _mapping(_mapping(results.get("ttl")).get("analysis"))
    if ttl_analysis:
        signals["ttl_reachability_samples"] = _signal(
            observation=(
                f"Sampled TTLs without a completed TCP connection: "
                f"{ttl_analysis.get('non_connecting_ttls', ttl_analysis.get('silent_ttls', []))}; "
                f"lowest sampled TTL that connected: {ttl_analysis.get('min_ttl_to_connect')}."
            ),
            inference="This bounds sampled reachability only; it does not identify a DPI hop.",
            strength="context",
            limitations=[
                "TCP connect APIs do not expose every ICMP Time Exceeded message consistently.",
                "The sampled TTL sequence is sparse and cannot locate an exact hop.",
            ],
        )

    rst = _mapping(results.get("rst"))
    if rst:
        delay = (rst.get("response_delay") or rst.get("rst_timing") or {}).get("median_ms")
        signals["post_connect_tcp_outcome"] = _signal(
            observation=(
                f"Dominant post-connect outcome: {rst.get('dominant_outcome', rst.get('dominant_verdict', 'unknown'))}; "
                f"median delay: {delay} ms."
            ),
            inference="Timing alone cannot determine whether a reset/close came from the server or an intermediary.",
            strength="context",
            limitations=["Packet capture at one side cannot rule out source-address spoofing."],
        )

    malformed = _rows(results.get("malformed_tls"))
    if malformed:
        response_count = sum(
            1 for row in malformed if row.get("dominant_response") in RESPONSE_OUTCOMES | {"tcp_reset"}
        )
        signals["malformed_tls_response_profile"] = _signal(
            observation=f"{response_count}/{len(malformed)} malformed ClientHello variants received a response or reset.",
            inference="At least one parser on the path or destination handled these inputs; its location is unknown.",
            strength="context",
            limitations=["Response latency is not comparable to TCP handshake RTT without a controlled server baseline."],
        )

    ip_rows = _rows(results.get("ip_blocking"))
    destination_dependent = [r for r in ip_rows if r.get("classification") in {"destination_dependent", "sni_ip_correlation"}]
    if destination_dependent:
        signals["destination_dependent_tls_outcome"] = _signal(
            observation=f"TLS outcomes differed across destination IPs for {len(destination_dependent)} hostname(s).",
            inference="Destination address affects the outcome; this does not identify whether policy is on-path or server-side.",
            strength="moderate",
            limitations=["The destination IPs are operated by different providers and are not equivalent controlled endpoints."],
        )

    http_rows = _rows(results.get("http_host"))
    host_dependent = [r for r in http_rows if r.get("classification") in {"host_dependent_no_response", "host_dependent_reset", "host_filtered", "host_rst"}]
    if host_dependent:
        signals["http_host_differential"] = _signal(
            observation=f"HTTP outcomes differed by Host header for {len(host_dependent)} hostname(s).",
            inference="Visible HTTP Host content affects the result, either on-path or at the destination.",
            strength="moderate",
            limitations=["The target is not a controlled HTTP virtual host for all tested names."],
        )

    dns_rows = _rows(results.get("dns"))
    divergent = [r for r in dns_rows if r.get("verdict") in {"divergent", "resolver_divergence", "possible_poisoning", "suspicious_resolution"}]
    if divergent:
        signals["dns_resolver_divergence"] = _signal(
            observation=f"System and public resolvers returned different result sets for {len(divergent)} hostname(s).",
            inference="Resolver views differ; CDN geolocation, split DNS, filtering, or manipulation are all possible.",
            strength="context",
            limitations=["Non-overlapping CDN answers are normal and do not prove DNS poisoning."],
        )

    pcap_analysis = _mapping(_mapping(results.get("pcap")).get("analysis"))
    if pcap_analysis and not pcap_analysis.get("error"):
        signals["packet_capture"] = _signal(
            observation=(
                f"Capture contains {pcap_analysis.get('total_packets', 0)} packets, "
                f"{pcap_analysis.get('retransmissions', 0)} retransmissions, "
                f"{pcap_analysis.get('rst_packets', 0)} resets "
                f"({pcap_analysis.get('rst_with_target_source_ip', 'unknown')} with the target source IP) and "
                f"{pcap_analysis.get('tls_alerts', 0)} TLS alerts."
            ),
            inference="Packet evidence strengthens transport observations but one-sided capture does not locate a drop hop.",
            strength="direct_observation",
            attribution="client_vantage_only",
        )
    return signals


def _assessment(signals: dict[str, Any], samples: int) -> tuple[str, str]:
    differential = signals.get("tls_sni_differential") or {}
    if differential.get("strength") == "strong":
        # Strong repeatability is still behavior, not attributed interference,
        # while the target is not a controlled endpoint for every hostname.
        return "content_dependent_behavior_observed", "moderate" if samples >= 3 else "low"
    if differential.get("strength") == "moderate":
        return "content_dependent_behavior_observed", "low" if samples < 3 else "moderate"
    if signals:
        return "inconclusive", "low"
    return "insufficient_data", "none"


def generate(target: str, results: dict, profile: str | None = None, samples: int = 1) -> dict:
    signals = _collect_signals(results)
    assessment, confidence = _assessment(signals, samples)
    return {
        "schema_version": "2.0",
        "meta": {
            "run_id": str(uuid.uuid4()),
            "target": target,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": "dpi-probe",
            "version": VERSION,
            "profile": profile,
            "samples": samples,
        },
        "summary": {
            "assessment": assessment,
            "dpi_detected": None,
            "confidence": confidence,
            "signals": signals,
            "findings": [item["observation"] for item in signals.values()],
            "limitations": [
                "This run does not identify a specific DPI appliance or physical hop.",
                "Attribution requires a controlled endpoint or synchronized captures at both client and server.",
                "No response before a timeout is an observation, not proof of intentional dropping.",
            ],
        },
        "tests": results,
    }


def save(report: dict, path: str | None = None) -> str:
    os.makedirs("reports", exist_ok=True)
    if not path:
        target = str(report["meta"]["target"]).replace(".", "_").replace(":", "_")
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = f"reports/report_{target}_{ts}.json"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    markdown = Path(path).with_suffix('.md')
    if markdown == Path(path):
        markdown = Path(str(path) + '.md')
    lines = ['# Diagnostic réseau dpi-probe', '',
             f"Cible : {report['meta']['target']}", '',
             f"Conclusion : {report['summary']['assessment']}", '',
             'Les mesures brutes sont conservées dans le fichier JSON associé.', '']
    for name, signal in report['summary']['signals'].items():
        lines += [f'## {name}', '', f"Observation : {signal['observation']}", '',
                  f"Interprétation : {signal['inference']}", '',
                  f"Force du constat : {signal['strength']} - attribution : {signal['attribution']}", '']
        lines += [f'- {value}' for value in signal['limitations']] + ['']
    lines += ['## Sondes exécutées', '']
    for name, value in report.get('tests', {}).items():
        status = value.get('status', 'résultats détaillés dans le JSON') if isinstance(value, dict) else f'{len(value)} résultats' if isinstance(value, list) else 'voir JSON'
        lines += [f'- {name} : {status}']
    lines += ['', '## Limites', ''] + [f'- {value}' for value in report['summary']['limitations']]
    markdown.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return path


def print_summary(report: dict) -> None:
    summary = report["summary"]
    print("\n" + "=" * 64)
    print("  DPI-PROBE EVIDENCE REPORT")
    print(f"  Target      : {report['meta']['target']}")
    print(f"  Timestamp   : {report['meta']['timestamp']}")
    print("=" * 64)
    print(f"  Assessment  : {summary['assessment']}")
    print(f"  Confidence  : {summary['confidence']}")
    print("  DPI located : NO - attribution requires dual-vantage evidence")
    print("\n  Evidence:")
    for name, signal in summary["signals"].items():
        print(f"    - {name} [{signal['strength']}]")
        print(f"      observed : {signal['observation']}")
        print(f"      inference: {signal['inference']}")
    print("\n  Main limitations:")
    for limitation in summary["limitations"]:
        print(f"    - {limitation}")
    print("=" * 64)
