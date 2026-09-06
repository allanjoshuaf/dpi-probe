"""Evidence-bound explanations of tunnel failures; no network calls."""

from __future__ import annotations

from typing import Any


def assess(report: dict[str, Any]) -> dict[str, Any]:
    findings = []

    def add(code, stage, where, observation, causes, checks, confidence="limited"):
        findings.append(dict(code=code, stage=stage, location=where,
                             observation=observation, possible_causes=causes,
                             next_checks=checks, confidence=confidence))

    for row in (report.get("config") or {}).get("vless_outbounds", []):
        issues = row.get("issues", [])
        errors = [i for i in issues if i not in {
            "utls_enabled_official_sing_box_docs_do_not_recommend_it",
            "tls_certificate_verification_disabled", "reality_server_name_missing",
        }]
        if errors:
            add("configuration_issues", "configuration", "client configuration",
                f"Outbound index {row['index']}: {', '.join(errors)}",
                ["Invalid or incomplete local settings; affected outbound may not be selected."],
                ["Run sing-box check -c CONFIG.json locally.",
                 "Compare the selected client's UUID, public key, short ID, flow and SNI with the server settings without sharing credentials."], "high")

    descriptions = {
        "dns_resolution": ("DNS resolution", ["Resolver failure", "Incorrect name", "DNS interference"],
                           ["Resolve the tunnel hostname outside the TUN and compare with the configured server IP."]),
        "tcp_connect": ("TCP connection", ["Routing or firewall failure", "Server unavailable", "IP/port filtering"],
                        ["Check the server listener and firewall; repeat to the same IP/port using another network."]),
        "reality_or_tls_handshake": ("TLS / REALITY handshake", ["Client/server authentication settings mismatch", "Cover target unavailable", "Network interference"],
                                     ["Compare client and server logs for the same attempt; verify key, short ID, SNI and flow.", "Check server access to its cover target."]),
        "transport_closed": ("transport closure", ["Client or server closure", "Path interruption", "Idle timeout"],
                             ["Locate the first closure or unanswered sequence in synchronized client/server captures."]),
        "routing": ("local routing", ["Unavailable outbound or detour", "TUN routing loop"],
                    ["Verify the selected outbound and the physical route to the server endpoint."]),
        "clock_skew": ("authentication clock", ["Client/server clock mismatch", "Invalid timestamp"],
                       ["Check UTC clock synchronization on both hosts and the server's allowed time difference."]),
    }
    for category, count in (report.get("log") or {}).get("category_counts", {}).items():
        if count and category in descriptions:
            stage, causes, checks = descriptions[category]
            add("log_" + category, stage, "application log; physical location unresolved",
                f"{count} matching log line(s); scope and timestamps require verification.", causes, checks)

    active = report.get("active_checks") or {}
    tcp = active.get("tcp") or {}
    attempts = tcp.get("attempts", [])
    if tcp.get("resolution_error"):
        add("endpoint_dns_failed", "DNS resolution", "local resolver",
            "The active check could not resolve the endpoint.", ["DNS failure or invalid hostname"],
            ["Repeat with the actual server IP, and inspect the system DNS route."], "high")
    elif attempts and not any(a.get("status") == "connected" for a in attempts):
        add("endpoint_tcp_failed", "TCP connection", "client-to-server path or server",
            "All active TCP attempts failed before TLS/REALITY authentication.",
            ["Routing failure", "Host or network firewall", "Listener unavailable", "IP/port filtering"],
            ["Verify the physical interface and server listener.", "Capture both ends during the same attempt and repeat via a second network."], "moderate")
    elif attempts and any(a.get("status") != "connected" for a in attempts):
        add("endpoint_tcp_intermittent", "TCP connection", "path or server",
            "Only some active TCP attempts connected.", ["Intermittent loss", "Rate limiting", "Different resolved IPs"],
            ["Repeat with a fixed IP and compare per-attempt remote addresses."], "moderate")
    cover = active.get("tls_cover") or {}
    if cover:
        add("ordinary_tls_" + cover.get("status", "unknown"), "ordinary cover TLS", "endpoint or fallback target",
            "Ordinary TLS certificate verified." if cover.get("status") == "verified" else "Ordinary cover TLS check failed.",
            ["This check does not authenticate VLESS/REALITY and cannot validate its credentials."],
            ["Reproduce using the actual tunnel client and inspect both application logs."])

    pcap = report.get("pcap") or {}
    if report.get("pcap") is not None and not pcap.get("packet_count"):
        add("empty_client_capture", "capture", "unknown", "No endpoint packets in the client capture.",
            ["Wrong interface, endpoint or time window", "No attempt was made"],
            ["Capture on the physical interface while reproducing; use the IP present at capture time."], "high")
    for stream in pcap.get("streams", []):
        phase = stream["phase"]
        observation = f"Stream {stream['stream']}: {phase}."
        if "late_target_direction_reset_after_orderly_close" == phase:
            continue
        if "target_direction_reset" in phase:
            add("target_reset", "TCP reset", "origin unresolved", observation,
                ["Server or firewall reset", "On-path spoofed reset"],
                ["Check whether the identical reset is visible in the server capture."])
        elif "no_return_payload" in phase or "unacknowledged" in phase:
            acknowledged = stream.get("first_client_payload_acknowledged")
            add("unanswered_client_data", "first client data", "beyond client capture point", observation,
                (["Remote TCP stack acknowledged data but application may discard it", "Return-path loss", "Capture ended too early"]
                 if acknowledged else ["Forward or ACK return-path loss", "Server discard", "Incomplete capture"]),
                ["Compare sequence coverage at both ends and inspect the server REALITY log."])
        elif "handshake_not_completed" in phase:
            add("tcp_setup_unobserved", "TCP connection", "path or capture window", observation,
                ["No SYN-ACK returned", "Capture started late or missed packets"],
                ["Start both captures before connecting; verify whether the server receives the SYN."])
        elif "retransmissions" in phase:
            add("transport_retransmissions", "data transfer", "path or capture", observation,
                ["Packet loss or reordering", "Congestion", "MTU issue", "Capture artifacts"],
                ["Inspect sustained retransmissions, zero windows and size-dependent failures at both ends; isolated retransmissions are normal."])
        elif "bidirectional_data" in phase:
            add("bidirectional_data", "data exchange", "between endpoints", observation,
                ["Encrypted bytes in both directions do not prove successful REALITY authentication or access to the inner destination."],
                ["Confirm a successful request through the selected tunnel and correlate it with application logs."])

    dual = report.get("dual_pcap") or {}
    mappings = {
        "forward_path_packet_divergence": "client → server, between capture points",
        "reverse_path_packet_divergence": "server → client, between capture points",
        "bidirectional_packet_divergence_between_vantages": "both directions, between capture points",
        "reset_visible_at_client_but_absent_at_server_vantage": "reset appears between server and client capture points",
        "reset_visible_at_server_vantage": "reset visible at the server capture point",
    }
    if dual.get("assessment") in mappings:
        add("dual_" + dual["assessment"], "packet divergence / reset", mappings[dual["assessment"]],
            f"Dual capture assessment: {dual['assessment']}.",
            ["Path loss or filtering", "Capture loss, incomplete window or asymmetric capture"],
            ["Verify both captures cover the same complete attempt and check capture drop counters.",
             "Repeat on another network with the same server and credentials; an exact router needs additional capture points."], "moderate")
    elif dual:
        add("dual_capture_scope", "capture comparison", "unresolved", dual["assessment"],
            ["No localized failure established by this comparison."],
            ["Check unmatched streams and capture coverage; absence of divergence does not establish a working tunnel."])

    return {
        "status": "evidence_available" if findings else "insufficient_evidence",
        "blocking_confirmed": None,
        "exact_hop": None,
        "findings": findings,
        "limitations": [
            "Confidence refers to the observation, not to a proven censorship cause.",
            "Config, logs, active checks and captures may describe different attempts; no automatic temporal correlation is claimed.",
            "One vantage cannot locate a silent drop. Two vantages bound a divergence, not an exact physical router.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    assessment = report["diagnosis"]
    lines = ["# Diagnostic VLESS / REALITY", "", f"Date UTC : {report['timestamp']}", "",
             "Ce rapport distingue observations, causes possibles et vérifications. Un blocage DPI n'est pas confirmé automatiquement.", ""]
    if not assessment["findings"]:
        lines += ["Preuves insuffisantes : fournir un journal de reproduction ou une capture du tunnel.", ""]
    for finding in assessment["findings"]:
        lines += [f"## {finding['stage']}", "", f"Où : {finding['location']}", "",
                  f"Observation : {finding['observation']}", "", f"Confiance dans l'observation : {finding['confidence']}", "",
                  "Causes possibles :", ""]
        lines += [f"- {cause}" for cause in finding["possible_causes"]]
        lines += ["", "Pour trancher :", ""]
        lines += [f"- {check}" for check in finding["next_checks"]]
        lines.append("")
    lines += ["## Limites", ""] + [f"- {item}" for item in assessment["limitations"]]
    lines += ["", "## Données à compléter", ""] + [f"- {item}" for item in report["data_needed_for_localization"]]
    return "\n".join(lines) + "\n"
