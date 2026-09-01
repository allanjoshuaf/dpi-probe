"""Packet-level tunnel timelines and dual-vantage capture comparison."""

from __future__ import annotations

import collections
import ipaddress
import json
import socket
import statistics
import subprocess
from pathlib import Path
from typing import Any

from src.pcap import find_tshark


def parse_endpoint(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, separator, port_text = value[1:].partition("]:")
    else:
        host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise ValueError("endpoint must use HOST:PORT (IPv6 must be [ADDRESS]:PORT)")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("endpoint port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port must be between 1 and 65535")
    return host, port


def resolve_endpoint(host: str, port: int) -> list[str]:
    addresses = {
        row[4][0]
        for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    }
    return sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value))


def _run_tshark(
    pcap_path: str,
    fields: list[str],
    display_filter: str,
    absolute_sequence_numbers: bool = True,
) -> list[str]:
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("tshark was not found")
    if not Path(pcap_path).is_file():
        raise FileNotFoundError(pcap_path)
    command = [tshark, "-n"]
    if absolute_sequence_numbers:
        command.extend(["-o", "tcp.relative_sequence_numbers:FALSE"])
    command.extend(["-r", pcap_path, "-Y", display_filter, "-T", "fields"])
    for field in fields:
        command.extend(["-e", field])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"tshark exited with {completed.returncode}")
    return [line for line in completed.stdout.splitlines() if line.strip()]


PACKET_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.time_relative",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.ttl", "ipv6.hlim",
    "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.len",
    "tcp.flags", "tcp.stream", "tcp.analysis.retransmission",
    "tcp.analysis.lost_segment", "tcp.analysis.duplicate_ack",
    "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
    "tcp.analysis.zero_window", "tcp.analysis.ack_rtt",
    "tls.handshake.type", "tls.handshake.extensions_server_name",
    "tls.record.content_type", "tls.alert_message",
]


def _endpoint_display_filter(endpoint_addresses: list[str], port: int) -> str:
    address_filters = []
    for address in endpoint_addresses:
        parsed = ipaddress.ip_address(address)
        address_filters.append(f"{'ipv6.addr' if parsed.version == 6 else 'ip.addr'} == {address}")
    return f"tcp.port == {port} and ({' or '.join(address_filters)})"


def extract_packets(pcap_path: str, endpoint_addresses: list[str], port: int) -> list[dict[str, Any]]:
    display_filter = _endpoint_display_filter(endpoint_addresses, port)
    rows = _run_tshark(pcap_path, PACKET_FIELDS, display_filter)
    packets = []
    for line in rows:
        values = line.split("\t")
        values += [""] * (len(PACKET_FIELDS) - len(values))
        row = dict(zip(PACKET_FIELDS, values))
        first = lambda value: value.split(",", 1)[0] if value else ""
        src = first(row["ip.src"]) or first(row["ipv6.src"])
        dst = first(row["ip.dst"]) or first(row["ipv6.dst"])
        src_port = int(first(row["tcp.srcport"]) or 0)
        dst_port = int(first(row["tcp.dstport"]) or 0)
        direction = "client_to_server" if dst_port == port else "server_to_client" if src_port == port else "unknown"
        flags = int(first(row["tcp.flags"]), 0) if row["tcp.flags"] else 0
        handshake_text = row["tls.handshake.type"].split(",", 1)[0]
        packet = {
            "frame": int(first(row["frame.number"])),
            "time_epoch": float(first(row["frame.time_epoch"])),
            "time_relative": float(first(row["frame.time_relative"])),
            "src": src,
            "dst": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "direction": direction,
            "seq": int(first(row["tcp.seq"]) or 0),
            "ack": int(first(row["tcp.ack"]) or 0),
            "payload_len": int(first(row["tcp.len"]) or 0),
            "flags": flags,
            "stream": first(row["tcp.stream"]),
            "ttl": int((first(row["ip.ttl"]) or first(row["ipv6.hlim"])) or 0),
            "retransmission": bool(row["tcp.analysis.retransmission"]),
            "lost_segment": bool(row["tcp.analysis.lost_segment"]),
            "duplicate_ack": bool(row["tcp.analysis.duplicate_ack"]),
            "fast_retransmission": bool(row["tcp.analysis.fast_retransmission"]),
            "spurious_retransmission": bool(row["tcp.analysis.spurious_retransmission"]),
            "zero_window": bool(row["tcp.analysis.zero_window"]),
            "ack_rtt_ms": round(float(first(row["tcp.analysis.ack_rtt"])) * 1000, 3) if row["tcp.analysis.ack_rtt"] else None,
            "tls_handshake_type": int(handshake_text) if handshake_text.isdigit() else None,
            "tls_sni": first(row["tls.handshake.extensions_server_name"]) or None,
            "tls_record_content_type": first(row["tls.record.content_type"]) or None,
            "tls_alert": first(row["tls.alert_message"]) or None,
            "syn": bool(flags & 0x02),
            "ack_flag": bool(flags & 0x10),
            "rst": bool(flags & 0x04),
            "fin": bool(flags & 0x01),
        }
        packets.append(packet)
    return packets


def _exact_analysis_flag_counts(
    pcap_path: str,
    endpoint_addresses: list[str],
    port: int,
) -> dict[str, dict[str, int]]:
    """Ask TShark for analysis flags in a filter so lazy fields are populated."""
    fields = {
        "retransmissions": "tcp.analysis.retransmission",
        "fast_retransmissions": "tcp.analysis.fast_retransmission",
        "spurious_retransmissions": "tcp.analysis.spurious_retransmission",
        "lost_segment_indications": "tcp.analysis.lost_segment",
        "duplicate_acks": "tcp.analysis.duplicate_ack",
        "zero_windows": "tcp.analysis.zero_window",
    }
    base = _endpoint_display_filter(endpoint_addresses, port)
    result = {
        "client_to_server": {name: 0 for name in fields},
        "server_to_client": {name: 0 for name in fields},
    }
    # Run one filter per lazy analysis field. Wireshark may short-circuit an
    # OR expression after the generic retransmission flag and then omit the
    # more specific fast/spurious fields from -T fields output.
    for name, field in fields.items():
        rows = _run_tshark(
            pcap_path,
            ["tcp.srcport", "tcp.dstport"],
            f"({base}) and {field}",
            absolute_sequence_numbers=False,
        )
        for line in rows:
            values = line.split("\t")
            values += [""] * (2 - len(values))
            src_port = int(values[0].split(",", 1)[0] or 0)
            dst_port = int(values[1].split(",", 1)[0] or 0)
            direction = "client_to_server" if dst_port == port else "server_to_client" if src_port == port else None
            if direction:
                result[direction][name] += 1
    return result


def _numeric_stats(values: list[float]) -> dict[str, Any]:
    clean = sorted(values)
    if not clean:
        return {"count": 0, "min": None, "median": None, "mean": None, "p95": None, "max": None}
    p95_index = min(int((len(clean) - 1) * 0.95), len(clean) - 1)
    return {
        "count": len(clean),
        "min": round(clean[0], 3),
        "median": round(statistics.median(clean), 3),
        "mean": round(statistics.mean(clean), 3),
        "p95": round(clean[p95_index], 3),
        "max": round(clean[-1], 3),
    }


def summarize_transport(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize packet mechanics without converting them into DPI claims."""
    by_direction = {}
    for direction in ("client_to_server", "server_to_client"):
        rows = [packet for packet in packets if packet["direction"] == direction]
        by_direction[direction] = {
            "packets": len(rows),
            "payload_bytes": sum(packet["payload_len"] for packet in rows),
            "retransmissions": sum(bool(packet.get("retransmission")) for packet in rows),
            "fast_retransmissions": sum(bool(packet.get("fast_retransmission")) for packet in rows),
            "spurious_retransmissions": sum(bool(packet.get("spurious_retransmission")) for packet in rows),
            "lost_segment_indications": sum(bool(packet.get("lost_segment")) for packet in rows),
            "duplicate_acks": sum(bool(packet.get("duplicate_ack")) for packet in rows),
            "zero_windows": sum(bool(packet.get("zero_window")) for packet in rows),
            "resets": sum(bool(packet.get("rst")) for packet in rows),
        }

    client_hellos = [packet for packet in packets if packet.get("tls_handshake_type") == 1]
    server_hellos = [packet for packet in packets if packet.get("tls_handshake_type") == 2]
    sni_counts = collections.Counter(
        packet["tls_sni"] for packet in client_hellos if packet.get("tls_sni")
    )
    client_hello_time = {}
    handshake_deltas = []
    for packet in packets:
        if packet.get("tls_handshake_type") == 1:
            client_hello_time.setdefault(packet["stream"], packet["time_epoch"])
        elif packet.get("tls_handshake_type") == 2 and packet["stream"] in client_hello_time:
            handshake_deltas.append(
                (packet["time_epoch"] - client_hello_time.pop(packet["stream"])) * 1000
            )

    target_ack_rtt = [
        packet["ack_rtt_ms"] for packet in packets
        if packet["direction"] == "server_to_client" and packet.get("ack_rtt_ms") is not None
    ]
    target_ttls = collections.Counter(
        packet["ttl"] for packet in packets
        if packet["direction"] == "server_to_client" and packet.get("ttl")
    )
    reset_ttls = collections.Counter(
        packet["ttl"] for packet in packets
        if packet["direction"] == "server_to_client" and packet.get("rst") and packet.get("ttl")
    )
    return {
        "packet_count": len(packets),
        "by_direction": by_direction,
        "target_ack_rtt_ms": _numeric_stats(target_ack_rtt),
        "tls": {
            "client_hello_count": len(client_hellos),
            "server_hello_count": len(server_hellos),
            "alert_packet_count": sum(bool(packet.get("tls_alert")) for packet in packets),
            "sni_counts": dict(sorted(sni_counts.items())),
            "clienthello_to_serverhello_ms": _numeric_stats(handshake_deltas),
        },
        "target_ttl_distribution": {str(key): value for key, value in sorted(target_ttls.items())},
        "target_direction_reset_ttl_distribution": {str(key): value for key, value in sorted(reset_ttls.items())},
        "limitations": [
            "TShark analysis flags are indications and can be affected by capture loss and NIC offload.",
            "A target-direction source address and matching TTL do not prove that the endpoint generated a reset.",
        ],
    }


def _packet_signature(packet: dict[str, Any]) -> tuple:
    # Absolute TCP sequence numbers survive normal IP NAT. Mask flags to the
    # state-changing bits to avoid differences in ECN/PSH representation.
    return (
        packet["direction"], packet["seq"], packet["ack"], packet["payload_len"],
        packet["flags"] & 0x17,
    )


def _important(packet: dict[str, Any]) -> bool:
    return packet["payload_len"] > 0 or packet["syn"] or packet["rst"] or packet["fin"]


def summarize_streams(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    streams: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for packet in packets:
        streams[packet["stream"]].append(packet)
    summaries = []
    for stream_id, rows in streams.items():
        rows.sort(key=lambda item: item["frame"])
        syn = any(row["direction"] == "client_to_server" and row["syn"] and not row["ack_flag"] for row in rows)
        syn_ack = any(row["direction"] == "server_to_client" and row["syn"] and row["ack_flag"] for row in rows)
        client_payload = sum(row["payload_len"] for row in rows if row["direction"] == "client_to_server")
        server_payload = sum(row["payload_len"] for row in rows if row["direction"] == "server_to_client")
        client_payload_packets = [
            row for row in rows
            if row["direction"] == "client_to_server" and row["payload_len"] > 0
        ]
        server_payload_packets = [
            row for row in rows
            if row["direction"] == "server_to_client" and row["payload_len"] > 0
        ]
        server_ack_max = max(
            (row["ack"] for row in rows if row["direction"] == "server_to_client" and row["ack_flag"]),
            default=None,
        )
        client_ack_max = max(
            (row["ack"] for row in rows if row["direction"] == "client_to_server" and row["ack_flag"]),
            default=None,
        )
        first_client_payload_end = (
            client_payload_packets[0]["seq"] + client_payload_packets[0]["payload_len"]
            if client_payload_packets else None
        )
        first_server_payload_end = (
            server_payload_packets[0]["seq"] + server_payload_packets[0]["payload_len"]
            if server_payload_packets else None
        )
        first_client_payload_acknowledged = bool(
            first_client_payload_end is not None
            and server_ack_max is not None
            and server_ack_max >= first_client_payload_end
        )
        first_server_payload_acknowledged = bool(
            first_server_payload_end is not None
            and client_ack_max is not None
            and client_ack_max >= first_server_payload_end
        )
        retransmissions = sum(row["retransmission"] for row in rows)
        resets = [row for row in rows if row["rst"]]
        reset_directions = {row["direction"] for row in resets}
        fin_directions = {row["direction"] for row in rows if row["fin"]}
        if resets and reset_directions == {"client_to_server"}:
            if client_payload and not server_payload:
                phase = (
                    "client_cleanup_reset_after_acknowledged_data_no_return_payload"
                    if first_client_payload_acknowledged
                    else "client_cleanup_reset_after_unacknowledged_data"
                )
            elif server_payload:
                phase = "client_reset_after_response"
            else:
                phase = "client_reset_during_tcp_setup"
        elif (
            resets
            and "server_to_client" in reset_directions
            and {"client_to_server", "server_to_client"}.issubset(fin_directions)
        ):
            phase = "late_target_direction_reset_after_orderly_close"
        elif resets and "server_to_client" in reset_directions:
            phase = "target_direction_reset_after_data" if client_payload or server_payload else "target_direction_reset_during_tcp_setup"
        elif client_payload and not server_payload and retransmissions:
            phase = (
                "client_data_acknowledged_no_return_payload_with_retransmissions"
                if first_client_payload_acknowledged
                else "client_data_unacknowledged_with_retransmissions"
            )
        elif client_payload and server_payload and retransmissions:
            phase = "established_flow_with_retransmissions" if syn_ack else "established_flow_with_retransmissions_partial_capture"
        elif client_payload and server_payload:
            phase = "bidirectional_data_observed" if syn_ack else "bidirectional_data_observed_partial_capture"
        elif syn and syn_ack:
            phase = "tcp_connected_no_payload_observed"
        elif not syn_ack:
            phase = "tcp_handshake_not_completed_or_not_visible_in_capture"
        else:
            phase = "partial_capture"
        summaries.append({
            "stream": stream_id,
            "phase": phase,
            "first_time_epoch": rows[0]["time_epoch"],
            "last_time_epoch": rows[-1]["time_epoch"],
            "duration_ms": round((rows[-1]["time_epoch"] - rows[0]["time_epoch"]) * 1000, 3),
            "packet_count": len(rows),
            "client_payload_bytes": client_payload,
            "server_payload_bytes": server_payload,
            "server_ack_max": server_ack_max,
            "client_ack_max": client_ack_max,
            "first_client_payload_acknowledged": first_client_payload_acknowledged,
            "first_server_payload_acknowledged": first_server_payload_acknowledged,
            "retransmissions": retransmissions,
            "reset_count": len(resets),
            "reset_directions": sorted(reset_directions),
            "last_event": {
                "frame": rows[-1]["frame"],
                "direction": rows[-1]["direction"],
                "payload_len": rows[-1]["payload_len"],
                "rst": rows[-1]["rst"],
                "fin": rows[-1]["fin"],
                "retransmission": rows[-1]["retransmission"],
            },
        })
    return sorted(summaries, key=lambda item: item["first_time_epoch"])


def analyze_single_pcap(pcap_path: str, endpoint: str) -> dict[str, Any]:
    host, port = parse_endpoint(endpoint)
    addresses = resolve_endpoint(host, port)
    packets = extract_packets(pcap_path, addresses, port)
    transport_metrics = summarize_transport(packets)
    exact_flags = _exact_analysis_flag_counts(pcap_path, addresses, port)
    for direction, counts in exact_flags.items():
        transport_metrics["by_direction"][direction].update(counts)
    return {
        "pcap": pcap_path,
        "endpoint": endpoint,
        "resolved_addresses": addresses,
        "packet_count": len(packets),
        "transport_metrics": transport_metrics,
        "streams": summarize_streams(packets),
        "limitations": [
            "A client-only capture identifies the failure phase, not the physical drop hop.",
            "Encrypted tunnel payloads do not reveal the inner destination.",
        ],
    }


def _unmatched(source: list[dict[str, Any]], other: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Presence matching avoids false divergence from duplicate packets produced
    # by Linux "any" captures or different retransmission visibility.
    signatures = {_packet_signature(row) for row in other if _important(row)}
    return [
        packet for packet in source
        if _important(packet) and _packet_signature(packet) not in signatures
    ]


def compare_vantages(client_pcap: str, server_pcap: str, endpoint: str) -> dict[str, Any]:
    host, port = parse_endpoint(endpoint)
    addresses = resolve_endpoint(host, port)
    client_packets = extract_packets(client_pcap, addresses, port)
    server_packets = extract_packets(server_pcap, addresses, port)
    client_only = _unmatched(client_packets, server_packets)
    server_only = _unmatched(server_packets, client_packets)

    forward_missing = [p for p in client_only if p["direction"] == "client_to_server" and p["payload_len"] > 0]
    reverse_missing = [p for p in server_only if p["direction"] == "server_to_client" and p["payload_len"] > 0]
    client_only_server_rst = [p for p in client_only if p["direction"] == "server_to_client" and p["rst"]]
    server_resets = [p for p in server_packets if p["direction"] == "server_to_client" and p["rst"]]
    matched_server_reset = bool(server_resets) and not client_only_server_rst

    if client_only_server_rst:
        assessment = "reset_visible_at_client_but_absent_at_server_vantage"
    elif forward_missing and reverse_missing:
        assessment = "bidirectional_packet_divergence_between_vantages"
    elif forward_missing:
        assessment = "forward_path_packet_divergence"
    elif reverse_missing:
        assessment = "reverse_path_packet_divergence"
    elif matched_server_reset:
        assessment = "reset_visible_at_server_vantage"
    else:
        assessment = "no_material_divergence_in_matched_packets"

    def compact(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {key: row[key] for key in (
                "frame", "time_epoch", "direction", "seq", "ack", "payload_len",
                "flags", "rst", "retransmission",
            )}
            for row in rows[:20]
        ]

    result = {
        "assessment": assessment,
        "endpoint": endpoint,
        "resolved_addresses": addresses,
        "client_packet_count": len(client_packets),
        "server_packet_count": len(server_packets),
        "forward_payload_packets_missing_at_server": len(forward_missing),
        "reverse_payload_packets_missing_at_client": len(reverse_missing),
        "server_to_client_resets_seen_only_at_client": len(client_only_server_rst),
        "server_to_client_resets_seen_at_server": len(server_resets),
        "first_forward_divergences": compact(forward_missing),
        "first_reverse_divergences": compact(reverse_missing),
        "client_only_reset_details": compact(client_only_server_rst),
        "client_streams": summarize_streams(client_packets),
        "server_streams": summarize_streams(server_packets),
        "limitations": [
            "Capture loss, NIC offload, asymmetric routing, or an incomplete capture can mimic divergence.",
            "Sequence matching locates a difference between capture points, not the exact router that caused it.",
            "For best results disable capture filters other than endpoint/port and synchronize system clocks.",
        ],
    }
    return result


def save_analysis(data: dict[str, Any], path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    return path
