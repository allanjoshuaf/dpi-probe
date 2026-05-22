import json
import datetime
import socket
def generate(target: str, results: dict) -> dict:
    """Build a structured JSON report from probe results"""

    report = {
        "meta": {
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tool": "dpi-probe",
            "version": "0.1.0",
        },
        "summary": {
            "dpi_detected": False,
            "confidence": None,
            "findings": [],
        },
        "tests": results,
    }

    findings = []
    score = 0

    # TCP
    tcp = results.get("tcp_443", {})
    if tcp.get("status") == "timeout":
        findings.append("Port 443 silently dropped - possible DPI block")
        score += 1

    # SNI
    sni_results = results.get("sni", [])
    blocked = [r for r in sni_results if r.get("dominant_response") == "silent_drop" or r.get("response_type") == "silent_drop"]
    if blocked:
        domains = [r["sni"] for r in blocked]
        findings.append(f"SNI silent drop detected for: {', '.join(domains)}")
        score += 2

    # TTL
    ttl = results.get("ttl", {})
    analysis = ttl.get("analysis", {})
    if analysis.get("suspicious"):
        findings.append(analysis.get("reason", "TTL anomaly detected"))
        score += 2

    # RST
    rst = results.get("rst", {})
    if rst.get("verdict") == "middlebox":
        findings.append(f"RST from middlebox response at {rst.get('rst_timing_ms')}ms vs {rst.get('rtt_ms')}ms baseline")
        score += 3

    # Malformed TLS
    malformed = results.get("malformed_tls", []) or []
    tcp_rtt = results.get("tcp_443", {}).get("rtt_ms")
    if tcp_rtt:
        fast_responses = [
            r for r in malformed
            if r.get("rtt_stats", {}).get("median_ms") and
            r["rtt_stats"]["median_ms"] < tcp_rtt * 0.6
        ]
        if fast_responses:
            findings.append("Malformed TLS responses faster than baseline middlebox TLS parser active")
            score += 3

    # Confidence
    if score >= 8:
        confidence = "high"
    elif score >= 4:
        confidence = "medium"
    else:
        confidence = "low"

    report["summary"]["dpi_detected"] = score >= 4
    report["summary"]["confidence"] = confidence
    report["summary"]["score"] = score
    report["summary"]["findings"] = findings

    return report


def save(report: dict, path: str = None) -> str:
    if not path:
        target = report["meta"]["target"].replace(".", "_")
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = f"report_{target}_{ts}.json"

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return path


def print_summary(report: dict):
    s = report["summary"]
    print("\n" + "=" * 50)
    print(f"  DPI PROBE REPORT")
    print(f"  Target     : {report['meta']['target']}")
    print(f"  Timestamp  : {report['meta']['timestamp']}")
    print("=" * 50)
    print(f"  DPI detected  : {'YES' if s['dpi_detected'] else 'NO'}")
    print(f"  Confidence    : {s['confidence'].upper()}")
    print(f"  Score         : {s['score']}/10")
    print(f"\n  Findings :")
    for f in s["findings"]:
        print(f"    → {f}")
    print("=" * 50)
