"""Observe post-connect TCP outcomes; packet origin requires packet capture."""

from __future__ import annotations

import socket
import time

from src.stats import summarize, summarize_status


def probe_post_connect_outcome(
    target_ip: str,
    host: str,
    port: int = 443,
    timeout: float = 3.0,
) -> dict:
    result = {
        "target": target_ip,
        "port": port,
        "host": host,
        "tcp_connect_ms": None,
        "response_delay_ms": None,
        "outcome": None,
        "bytes_received": 0,
        "origin": "unresolved_without_packet_capture",
        "error": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        started = time.monotonic()
        sock.connect((target_ip, port))
        result["tcp_connect_ms"] = round((time.monotonic() - started) * 1000, 2)
        request = f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
        started = time.monotonic()
        sock.sendall(request)
        data = sock.recv(4096)
        result["response_delay_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["bytes_received"] = len(data)
        result["outcome"] = "application_data" if data else "connection_closed_no_data"
    except ConnectionResetError as exc:
        result["response_delay_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["outcome"] = "tcp_reset_observed"
        result["error"] = str(exc)
    except socket.timeout:
        result["outcome"] = "no_response_before_timeout"
    except OSError as exc:
        result["outcome"] = "socket_error"
        result["error"] = str(exc)
    finally:
        sock.close()
    return result


def run(target_ip: str, samples: int = 1, host: str = "instagram.com") -> dict:
    print("\n[*] Post-Connect TCP Outcome Test")
    print(f"    Target  : {target_ip}:443")
    print(f"    Payload : plaintext HTTP with Host={host}")
    print("    Warning : this is not a valid TLS request; origin needs PCAP")
    print(f"    Samples : {samples}\n")

    attempts = [probe_post_connect_outcome(target_ip, host) for _ in range(samples)]
    connect_stats = summarize([row.get("tcp_connect_ms") for row in attempts])
    delay_stats = summarize([row.get("response_delay_ms") for row in attempts])
    outcome_stats = summarize_status([row.get("outcome") for row in attempts])
    dominant = outcome_stats.get("dominant") or "unknown"

    print(f"    TCP connect median : {connect_stats['median_ms']} ms")
    print(f"    Response median    : {delay_stats['median_ms']} ms")
    print(f"    Dominant outcome   : {dominant}")
    print("    Origin             : unresolved_without_packet_capture")

    return {
        "target": target_ip,
        "host": host,
        "samples": samples,
        "tcp_connect": connect_stats,
        "response_delay": delay_stats,
        "dominant_outcome": dominant,
        "outcome_breakdown": outcome_stats["breakdown"],
        "origin_assessment": "unresolved_without_packet_capture",
        "attempts": attempts,
    }


# Compatibility for callers that imported the old function name.
test_rst_origin = probe_post_connect_outcome
