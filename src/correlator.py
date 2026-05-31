import time

def correlate(sni_results: list, pcap_analysis: dict) -> dict:
    """
    Correlate SNI test results with PCAP events by timestamp.
    Produces per-domain evidence summary.
    """
    client_hellos = pcap_analysis.get("client_hello_details", [])
    tls_alerts = pcap_analysis.get("tls_alert_details", [])
    rst_details = pcap_analysis.get("rst_details", [])

    margin = 1.0  # seconds tolerance

    def events_in_window(events, start, end, time_key="time_epoch"):
        result = []
        for e in events:
            try:
                t = float(e.get(time_key, 0))
                if start - margin <= t <= end + margin:
                    result.append(e)
            except Exception:
                pass
        return result

    by_domain = {}

    for attempt in sni_results:
        sni = attempt.get("sni")
        if not sni:
            continue

        start = attempt.get("start_time_epoch")
        end = attempt.get("end_time_epoch")
        outcome = attempt.get("response_type", "unknown")

        if not start or not end:
            continue

        hellos = events_in_window(client_hellos, start, end)
        alerts = events_in_window(tls_alerts, start, end)
        rsts = events_in_window(rst_details, start, end)

        if sni not in by_domain:
            by_domain[sni] = {
                "attempts": 0,
                "outcomes": [],
                "client_hellos": 0,
                "tls_alerts": 0,
                "rst_packets": 0,
                "retransmissions": 0,
                "evidence": None,
            }

        by_domain[sni]["attempts"] += 1
        by_domain[sni]["outcomes"].append(outcome)
        by_domain[sni]["client_hellos"] += len(hellos)
        by_domain[sni]["tls_alerts"] += len(alerts)
        by_domain[sni]["rst_packets"] += len(rsts)

    # Determine evidence per domain
    for sni, data in by_domain.items():
        outcomes = data["outcomes"]
        dominant = max(set(outcomes), key=outcomes.count)
        data["dominant_outcome"] = dominant

        if dominant == "silent_drop" and data["client_hellos"] > 0:
            data["evidence"] = "clienthello_seen_no_response"
        elif dominant == "tls_alert" and data["tls_alerts"] > 0:
            data["evidence"] = "clienthello_seen_tls_alert_received"
        elif dominant == "tcp_reset" and data["rst_packets"] > 0:
            data["evidence"] = "clienthello_seen_rst_received"
        else:
            data["evidence"] = "inconclusive"

    return by_domain


def print_summary(by_domain: dict):
    print("\n[*] Per-Domain PCAP Correlation")
    for sni, data in by_domain.items():
        print(f"\n    {sni}")
        print(f"      attempts       : {data['attempts']}")
        print(f"      outcome        : {data['dominant_outcome']}")
        print(f"      client_hellos  : {data['client_hellos']}")
        print(f"      tls_alerts     : {data['tls_alerts']}")
        print(f"      rst_packets    : {data['rst_packets']}")
        print(f"      evidence       : {data['evidence']}")