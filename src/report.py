import json
import datetime
import socket
import uuid

def generate(target: str, results: dict, profile: str = None, samples: int = 1) -> dict:
    report = {
        "schema_version": "1.0",
        "meta": {
            "run_id": str(uuid.uuid4()),
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tool": "dpi-probe",
            "version": "0.1.0",
            "profile": profile,
            "samples": samples,
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
            "score": 3,
        }
        findings.append(f"SNI filtering observed for: {', '.join(domains)}")
    elif blocked:
        signals["sni_filtering"] = {
            "observation": "silent_drop detected but no clean baseline to compare",
            "confidence": "low",
            "score": 1,
        }

    # TTL
    ttl = results.get("ttl", {})
    analysis = ttl.get("analysis", {})
    silent_ttls = analysis.get("silent_ttls", [])
    if silent_ttls and analysis.get("min_ttl_to_connect"):
        signals["ttl_suppression"] = {
            "observation": f"No ICMP TTL exceeded on hops {silent_ttls}, first connection at TTL {analysis['min_ttl_to_connect']}",
            "confidence": "medium",
            "score": 2,
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
            "score": 2,
        }
        findings.append(f"RST timing consistent with closer responder - {ratio}x baseline")
    elif dominant_verdict == "ambiguous" and ratio and ratio < 0.5:
        signals["rst_timing"] = {
            "observation": f"RST timing {ratio}x baseline - inconclusive without packet capture",
            "confidence": "low",
            "score": 1,
        }
    else:
        signals["rst_timing"] = {
            "observation": f"RST timing {ratio}x baseline - no anomaly detected",
            "confidence": "none",
            "score": 0,
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
                "score": 2,
            }
            findings.append("Malformed TLS responses faster than clean SNI baseline - timing consistent with middlebox TLS parser")
        else:
            signals["tls_parser"] = {
                "observation": f"Malformed TLS responses within clean SNI baseline range ({clean_baseline}ms)  inconclusive",
                "confidence": "low",
                "score": 0,
            }

    # IP Blocking classification
    ip_blocking = results.get("ip_blocking", []) or []
    pure_sni = [r for r in ip_blocking if r.get("classification") == "pure_sni_filtering"]
    sni_ip_corr = [r for r in ip_blocking if r.get("classification") == "sni_ip_correlation"]

    if pure_sni:
        domains = [r["sni"] for r in pure_sni]
        signals["ip_blocking"] = {
            "observation": f"pure SNI filtering on {len(pure_sni)} domain(s): {', '.join(domains)}",
            "confidence": "high",
            "score": 2,
        }
        findings.append(f"Pure SNI filtering observed across all tested IPs: {', '.join(domains)}")

    if sni_ip_corr:
        domains = [r["sni"] for r in sni_ip_corr]
        signals["sni_ip_correlation"] = {
            "observation": f"SNI+IP correlation on {len(sni_ip_corr)} domain(s): {', '.join(domains)}",
            "confidence": "medium",
            "score": 1,
        }
        findings.append(f"SNI+IP correlation observed: {', '.join(domains)}")

    # HTTP Host filtering
    http_host = results.get("http_host", []) or []
    host_filtered = [r for r in http_host if r.get("classification") == "host_filtered"]
    host_403 = [r for r in http_host if r.get("classification") == "response_403"]

    if host_filtered:
        domains = [r["host"] for r in host_filtered]
        signals["http_host_filtering"] = {
            "observation": f"HTTP Host filtering on {len(host_filtered)} domain(s): {', '.join(domains)}",
            "confidence": "medium",
            "score": 1,
        }
        findings.append(f"HTTP Host header filtering observed: {', '.join(domains)}")

    if host_403:
        domains = [r["host"] for r in host_403]
        signals["http_403_response"] = {
            "observation": f"HTTP 403 on {len(host_403)} domain(s): {', '.join(domains)} - likely server-side, not DPI",
            "confidence": "low",
            "score": 0,
        }

    # Overall score and confidence
    total_weight = sum(s["score"] for s in signals.values())
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
    max_score = sum([3, 2, 2, 2, 2, 1, 1])  # SNI + TTL + RST + TLS + ip_blocking + sni_ip_corr + http_host
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
    samples = report.get("meta", {}).get("samples", 1)
    reliability = "low (samples=1)" if samples <= 1 else f"medium (samples={samples})" if samples < 5 else f"high (samples={samples})"
    print(f"  Reliability   : {reliability}")
    print(f"\n  Findings :")
    for f in s["findings"]:
        print(f"    → {f}")
    print("=" * 50)
