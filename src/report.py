import json
import datetime
import socket
def generate(target: str, results: dict) -> dict:
    report = {
        "schema_version": "1.0",
        "meta": {
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tool": "dpi-probe",
            "version": "0.1.0",
        },
        "summary": {
            "dpi_detected": False,
            "confidence": None,
            "signals": {},
            "findings": [],
        },
        "tests": results,
    }

    findings = []
    signals = {}

    # SNI
    sni_results = results.get("sni", []) or []
    blocked = [r for r in sni_results if r.get("dominant_response") == "silent_drop"]
    clean_pass = [r for r in sni_results if r.get("category") == "clean" and r.get("dominant_response") in ["tls_alert", "server_hello"]]

    if blocked and clean_pass:
        domains = [r["sni"] for r in blocked]
        consistency = min([r["status_breakdown"].get("silent_drop", 0) for r in blocked])
        signals["sni_filtering"] = {
            "observation": f"silent_drop on {len(blocked)} domain(s): {', '.join(domains)}",
            "consistency": f"{int(consistency * 100)}%",
            "confidence": "high" if consistency >= 0.9 else "medium",
            "weight": 3,
        }
        findings.append(f"SNI filtering observed for: {', '.join(domains)}")
    elif blocked:
        signals["sni_filtering"] = {
            "observation": "silent_drop detected but no clean baseline to compare",
            "confidence": "low",
            "weight": 1,
        }

    # TTL
    ttl = results.get("ttl", {})
    analysis = ttl.get("analysis", {})
    silent_ttls = analysis.get("silent_ttls", [])
    if silent_ttls and analysis.get("min_ttl_to_connect"):
        signals["ttl_suppression"] = {
            "observation": f"No ICMP TTL exceeded on hops {silent_ttls}, first connection at TTL {analysis['min_ttl_to_connect']}",
            "confidence": "medium",
            "weight": 2,
        }
        findings.append(f"TTL/ICMP behavior consistent with suppression at hops {silent_ttls}")

    # RST
    rst = results.get("rst", {})
    dominant_verdict = rst.get("dominant_verdict")
    ratio = rst.get("ratio")
    if dominant_verdict == "middlebox":
        signals["rst_timing"] = {
            "observation": f"Response timing {ratio}x baseline - consistent with closer responder",
            "confidence": "medium",
            "weight": 2,
        }
        findings.append(f"RST timing consistent with closer responder - {ratio}x baseline")
    elif dominant_verdict == "ambiguous" and ratio and ratio < 0.5:
        signals["rst_timing"] = {
            "observation": f"RST timing {ratio}x baseline - inconclusive without packet capture",
            "confidence": "low",
            "weight": 1,
        }
    else:
        signals["rst_timing"] = {
            "observation": f"RST timing {ratio}x baseline - no anomaly detected",
            "confidence": "none",
            "weight": 0,
        }

    # Malformed TLS
    malformed = results.get("malformed_tls", []) or []
    clean_rtts = [
        r["rtt_stats"]["median_ms"] for r in sni_results
        if r.get("category") == "clean" and r.get("rtt_stats", {}).get("median_ms")
    ]
    clean_baseline = sorted(clean_rtts)[len(clean_rtts)//2] if clean_rtts else None

    if clean_baseline:
        fast = [r for r in malformed if r.get("rtt_stats", {}).get("median_ms") and r["rtt_stats"]["median_ms"] < clean_baseline * 0.6]
        if fast:
            signals["tls_parser"] = {
                "observation": f"{len(fast)} malformed TLS variant(s) responded faster than clean SNI baseline ({clean_baseline}ms)",
                "confidence": "medium",
                "weight": 2,
            }
            findings.append("Malformed TLS responses faster than clean SNI baseline - timing consistent with middlebox TLS parser")
        else:
            signals["tls_parser"] = {
                "observation": f"Malformed TLS responses within clean SNI baseline range ({clean_baseline}ms)  inconclusive",
                "confidence": "low",
                "weight": 0,
            }

    # Overall score and confidence
    total_weight = sum(s["weight"] for s in signals.values())
    high_signals = [s for s in signals.values() if s["confidence"] == "high"]
    medium_signals = [s for s in signals.values() if s["confidence"] == "medium"]

    if high_signals and medium_signals:
        confidence = "high"
    elif high_signals or len(medium_signals) >= 2:
        confidence = "medium"
    elif medium_signals:
        confidence = "low"
    else:
        confidence = "none"

    report["summary"]["dpi_detected"] = total_weight >= 3
    report["summary"]["confidence"] = confidence
    max_score = sum([3, 2, 2, 2])  # SNI + TTL + RST + TLS
    report["summary"]["score"] = f"{total_weight}/{max_score}"
    report["summary"]["signals"] = signals
    report["summary"]["findings"] = findings

    return report

def save(report: dict, path: str = None) -> str:
    import os
    os.makedirs("reports", exist_ok=True)

    if not path:
        target = report["meta"]["target"].replace(".", "_")
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = f"reports/report_{target}_{ts}.json"

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
    print(f"  Signal score  : {s['score']}")
    print(f"\n  Findings :")
    for f in s["findings"]:
        print(f"    → {f}")
    print("=" * 50)
