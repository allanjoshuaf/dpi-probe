import json

def load_report(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            result = json.load(f)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Failed to load report {path}: {exc}") from exc
    if not isinstance(result, dict):
        raise ValueError('A report must contain a JSON object')
    return result

def compare_sni(a: list, b: list) -> list:
    changes = []
    a_map = {r["sni"]: r for r in a}
    b_map = {r["sni"]: r for r in b}

    all_domains = set(a_map.keys()) | set(b_map.keys())

    for domain in sorted(all_domains):
        a_result = a_map.get(domain, {}).get("dominant_response", "missing")
        b_result = b_map.get(domain, {}).get("dominant_response", "missing")

        if a_result != b_result:
            changes.append({
                "domain": domain,
                "before": a_result,
                "after": b_result,
                "type": "sni_change",
            })

    return changes

def compare_ip_blocking(a: list, b: list) -> list:
    changes = []
    a_map = {r["sni"]: r for r in a}
    b_map = {r["sni"]: r for r in b}

    all_domains = set(a_map.keys()) | set(b_map.keys())

    for domain in sorted(all_domains):
        a_class = a_map.get(domain, {}).get("classification", "missing")
        b_class = b_map.get(domain, {}).get("classification", "missing")

        if a_class != b_class:
            changes.append({
                "domain": domain,
                "before": a_class,
                "after": b_class,
                "type": "ip_blocking_change",
            })

    return changes

def compare_http_host(a: list, b: list) -> list:
    changes = []
    a_map = {r["host"]: r for r in a}
    b_map = {r["host"]: r for r in b}

    all_hosts = set(a_map.keys()) | set(b_map.keys())

    for host in sorted(all_hosts):
        a_class = a_map.get(host, {}).get("classification", "missing")
        b_class = b_map.get(host, {}).get("classification", "missing")

        if a_class != b_class:
            changes.append({
                "domain": host,
                "before": a_class,
                "after": b_class,
                "type": "http_host_change",
            })

    return changes

def compare_signals(a: dict, b: dict) -> list:
    changes = []
    all_signals = set(a.keys()) | set(b.keys())

    for signal in sorted(all_signals):
        a_conf = a.get(signal, {}).get("strength", a.get(signal, {}).get("confidence", "missing"))
        b_conf = b.get(signal, {}).get("strength", b.get(signal, {}).get("confidence", "missing"))

        if a_conf != b_conf:
            changes.append({
                "signal": signal,
                "before": a_conf,
                "after": b_conf,
                "type": "signal_change",
            })

    return changes

def compare_rst(a: dict, b: dict) -> list:
    changes = []
    a_ratio = a.get("ratio")
    b_ratio = b.get("ratio")

    if a_ratio is not None and b_ratio is not None:
        diff = abs(a_ratio - b_ratio)
        if diff > 0.3:
            changes.append({
                "signal": "rst_ratio",
                "before": round(a_ratio, 2),
                "after": round(b_ratio, 2),
                "type": "rst_change",
                "note": f"Ratio changed by {round(diff, 2)}x",
            })

    a_verdict = a.get("dominant_verdict")
    b_verdict = b.get("dominant_verdict")

    if a_verdict != b_verdict:
        changes.append({
            "signal": "rst_verdict",
            "before": a_verdict,
            "after": b_verdict,
            "type": "rst_change",
        })

    return changes

def run(path_a: str, path_b: str):
    report_a = load_report(path_a)
    report_b = load_report(path_b)
    if any('diagnosis' not in item and ('meta' not in item or 'summary' not in item) for item in (report_a, report_b)):
        raise ValueError('Compare two detailed probe reports or tunnel diagnoses; standalone quick/ECH/capture results use different formats.')
    if "diagnosis" in report_a or "diagnosis" in report_b:
        if "diagnosis" not in report_a or "diagnosis" not in report_b:
            raise ValueError("compare two tunnel diagnoses or two probe reports, not mixed types")
        if report_a.get("endpoint") != report_b.get("endpoint"):
            print("[!] Endpoints differ: this is not an isolated network-path comparison.")
        changes = []
        codes_a = {f["code"] for f in report_a["diagnosis"]["findings"]}
        codes_b = {f["code"] for f in report_b["diagnosis"]["findings"]}
        for code in sorted(codes_a ^ codes_b):
            changes.append({"signal": code, "before": code in codes_a, "after": code in codes_b, "type": "diagnosis_change"})
        print("[*] Tunnel diagnosis comparison (finding presence only)")
        for change in changes:
            print(f"    {change['signal']}: {change['before']} -> {change['after']}")
        if not changes:
            print("    No change in finding codes; raw counts and timings may still differ.")
        print("    Keep server, credentials and client version constant; match reproduction windows before attributing a difference to the network.")
        return changes

    meta_a = report_a.get("meta", {})
    meta_b = report_b.get("meta", {})
    tests_a = report_a.get("tests", {})
    tests_b = report_b.get("tests", {})
    summary_a = report_a.get("summary", {})
    summary_b = report_b.get("summary", {})

    print("\n[*] dpi-probe compare mode")
    print(f"    A : {meta_a.get('target')} - {meta_a.get('timestamp')} - profile: {meta_a.get('profile', 'unknown')}")
    print(f"    B : {meta_b.get('target')} - {meta_b.get('timestamp')} - profile: {meta_b.get('profile', 'unknown')}")
    print()

    all_changes = []

    # SNI
    def rows(tests, name):
        value = tests.get(name)
        return value if isinstance(value, list) else []
    sni_changes = compare_sni(rows(tests_a, "sni"), rows(tests_b, "sni"))
    all_changes += sni_changes

    # IP blocking
    ip_changes = compare_ip_blocking(rows(tests_a, "ip_blocking"), rows(tests_b, "ip_blocking"))
    all_changes += ip_changes

    # HTTP Host
    http_changes = compare_http_host(rows(tests_a, "http_host"), rows(tests_b, "http_host"))
    all_changes += http_changes

    # Signals
    signal_changes = compare_signals(summary_a.get("signals", {}), summary_b.get("signals", {}))
    all_changes += signal_changes

    # RST
    rst_changes = compare_rst(tests_a.get("rst", {}), tests_b.get("rst", {}))
    all_changes += rst_changes

    # Evidence assessment (with legacy score fallback)
    assessment_a = summary_a.get("assessment", summary_a.get("score", "?"))
    assessment_b = summary_b.get("assessment", summary_b.get("score", "?"))
    conf_a = summary_a.get("confidence", "?")
    conf_b = summary_b.get("confidence", "?")

    profile_a = meta_a.get("profile", "unknown")
    profile_b = meta_b.get("profile", "unknown")

    print("=" * 50)
    print(f"  COMPARISON REPORT")
    print("=" * 50)
    print(f"  Profile    : {profile_a} → {profile_b}")
    print(f"  Assessment : {assessment_a} → {assessment_b}")
    print(f"  Confidence : {conf_a} → {conf_b}")

    if not all_changes:
        print("  No changes detected between the two reports.")
    else:
        print(f"  {len(all_changes)} change(s) detected:\n")
        for c in all_changes:
            if "domain" in c:
                print(f"    {c['domain']:<25} {c['before']} → {c['after']}")
            elif "signal" in c:
                note = f"  ({c.get('note', '')})" if c.get("note") else ""
                print(f"    {c['signal']:<25} {c['before']} → {c['after']}{note}")

    print("=" * 50)

    return all_changes
