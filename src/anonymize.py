import json
import datetime
import copy
import os

def anonymize_report(report: dict, isp: str = None, country: str = None) -> dict:
    """
    Produce a sanitized version of a report for voluntary sharing.
    Removes identifying information, rounds timestamps.
    """
    r = copy.deepcopy(report)

    # Round timestamp to nearest minute
    try:
        ts = datetime.datetime.fromisoformat(r["meta"]["timestamp"].replace("Z", "+00:00"))
        ts_rounded = ts.replace(second=0, microsecond=0)
        r["meta"]["timestamp"] = ts_rounded.isoformat().replace("+00:00", "Z")
    except (KeyError, TypeError, ValueError):
        # Older or partial reports may not carry a parseable timestamp.
        # Anonymization of the remaining fields can still proceed safely.
        pass

    # Remove identifying fields
    r["meta"].pop("run_id", None)
    r["meta"]["target"] = "redacted"

    # Add optional context
    if isp:
        r["meta"]["isp"] = isp
    if country:
        r["meta"]["country"] = country

    # Strip pcap paths
    if "pcap" in r.get("tests", {}):
        r["tests"]["pcap"].pop("pcap_path", None)
        r["tests"]["pcap"].pop("capture", None)

    # Remove raw test data — keep only summary and signals
    r.pop("tests", None)

    return r

def save_anonymized(report: dict, output_path: str = None) -> str:
    if not output_path:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M")
        profile = report.get("meta", {}).get("profile", "unknown")
        output_path = f"reports/anon_{profile}_{ts}.json"

    os.makedirs("reports", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path

def run(report_path: str, isp: str = None, country: str = None) -> str:
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load report: {e}")
        return None

    anonymized = anonymize_report(report, isp=isp, country=country)
    output_path = save_anonymized(anonymized)

    print(f"\n[*] Anonymized report saved → {output_path}")
    print(f"    Target    : redacted")
    print(f"    Timestamp : {anonymized['meta']['timestamp']} (rounded to minute)")
    print(f"    Profile   : {anonymized['meta'].get('profile', 'unknown')}")
    print(f"    ISP       : {anonymized['meta'].get('isp', 'not specified')}")
    print(f"    Assessment: {anonymized['summary'].get('assessment', anonymized['summary'].get('score', 'unknown'))}")
    print(f"    Confidence: {anonymized['summary']['confidence']}")

    return output_path
