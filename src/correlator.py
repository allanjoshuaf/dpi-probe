import time

def correlate(sni_results: list, pcap_analysis: dict) -> dict:
    """
    Correlate SNI test results with PCAP events by tcp.stream.
    Produces per-domain evidence summary.
    """
    client_hellos = pcap_analysis.get("client_hello_details", [])
    tls_alerts = pcap_analysis.get("tls_alert_details", [])
    rst_details = pcap_analysis.get("rst_details", [])
    retransmissions = pcap_analysis.get("retransmission_details", [])
    target_ip = pcap_analysis.get("target_ip")
    margin = 1.0

    def in_window(event, windows):
        try:
            t = float(event.get("time_epoch", 0))
        except Exception:
            return False

        for start, end in windows:
            if start - margin <= t <= end + margin:
                return True
        return False

    def events_for_streams(events, streams):
        if not streams:
            return []
        return [e for e in events if e.get("tcp_stream") in streams]

    hellos_by_sni = {}
    for hello in client_hellos:
        sni = hello.get("sni")
        if not sni:
            continue
        hellos_by_sni.setdefault(sni, []).append(hello)

    by_domain = {}
    for attempt in sni_results:
        sni = attempt.get("sni")
        if not sni:
            continue

        outcome = attempt.get("response_type", "unknown")
        start = attempt.get("start_time_epoch")
        end = attempt.get("end_time_epoch")

        if sni not in by_domain:
            by_domain[sni] = {
                "attempts": 0,
                "outcomes": [],
                "windows": [],
                "client_hellos": 0,
                "tls_alerts": 0,
                "rst_packets": 0,
                "server_rst_packets": 0,
                "client_rst_packets": 0,
                "retransmissions": 0,
                "tcp_streams": [],
                "evidence": None,
            }

        by_domain[sni]["attempts"] += 1
        by_domain[sni]["outcomes"].append(outcome)
        if start and end:
            by_domain[sni]["windows"].append((float(start), float(end)))

    # Determine evidence per domain
    for sni, data in by_domain.items():
        windows = data.pop("windows", [])
        hellos = [
            h for h in hellos_by_sni.get(sni, [])
            if in_window(h, windows)
        ]
        streams = {h.get("tcp_stream") for h in hellos if h.get("tcp_stream")}
        alerts = events_for_streams(tls_alerts, streams)
        rsts = events_for_streams(rst_details, streams)
        retrans = events_for_streams(retransmissions, streams)
        server_rsts = [
            r for r in rsts
            if target_ip and r.get("src") == target_ip
        ]
        client_rsts = [
            r for r in rsts
            if not target_ip or r.get("src") != target_ip
        ]

        data["client_hellos"] = len(hellos)
        data["tls_alerts"] = len(alerts)
        data["rst_packets"] = len(rsts)
        data["server_rst_packets"] = len(server_rsts)
        data["client_rst_packets"] = len(client_rsts)
        data["retransmissions"] = len(retrans)
        data["tcp_streams"] = sorted(streams)

        outcomes = data["outcomes"]
        dominant = max(set(outcomes), key=outcomes.count)
        data["dominant_outcome"] = dominant

        if dominant == "silent_drop" and data["client_hellos"] > 0:
            if data["tls_alerts"] == 0 and data["server_rst_packets"] == 0 and data["retransmissions"] > 0:
                data["evidence"] = "clienthello_seen_retransmissions_no_server_response"
            elif data["tls_alerts"] == 0 and data["server_rst_packets"] == 0:
                data["evidence"] = "clienthello_seen_no_response"
            elif data["server_rst_packets"] > 0:
                data["evidence"] = "clienthello_seen_server_rst"
            else:
                data["evidence"] = "clienthello_seen_mixed_stream_events"
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
        print(f"      server_rsts    : {data['server_rst_packets']}")
        print(f"      client_rsts    : {data['client_rst_packets']}")
        print(f"      retransmissions: {data['retransmissions']}")
        print(f"      tcp_streams    : {data['tcp_streams']}")
        print(f"      evidence       : {data['evidence']}")
