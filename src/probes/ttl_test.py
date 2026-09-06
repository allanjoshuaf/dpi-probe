"""Sample TCP reachability with selected outgoing TTL values."""

from __future__ import annotations

import socket
import time

from src.stats import summarize, summarize_status


DEFAULT_TTLS = [1, 2, 3, 5, 8, 13, 21, 32, 64]


def probe_ttl(target_ip: str, port: int, ttl: int, timeout: float = 2.0) -> dict:
    result = {"ttl": ttl, "outcome": None, "connect_ms": None, "socket_error": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)
    try:
        started = time.monotonic()
        sock.connect((target_ip, port))
        result["connect_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["outcome"] = "connected"
    except socket.timeout:
        result["outcome"] = "connect_timeout"
    except OSError as exc:
        # Error text and errno differ by platform and cannot reliably identify
        # the ICMP origin. Preserve the raw value instead of naming a hop.
        result["outcome"] = "socket_error"
        result["socket_error"] = {"errno": exc.errno, "message": str(exc)}
    finally:
        sock.close()
    return result


def test_ttl_hop(
    target_ip: str,
    port: int = 443,
    ttl_values: list[int] | None = None,
    silent: bool = False,
) -> list[dict]:
    values = ttl_values or DEFAULT_TTLS
    results = [probe_ttl(target_ip, port, ttl) for ttl in values]
    if not silent:
        for row in results:
            print(f"    TTL {row['ttl']:>3} -> {row['outcome']:<16} {row['connect_ms'] or ''}")
    return results


def analyze(results: list[dict]) -> dict:
    connected = [row["ttl"] for row in results if row["outcome"] == "connected"]
    non_connecting = [row["ttl"] for row in results if row["outcome"] != "connected"]
    return {
        "min_ttl_to_connect": min(connected) if connected else None,
        "non_connecting_ttls": non_connecting,
        "observation": "sampled_tcp_ttl_reachability",
        "attribution": "none",
        "limitations": [
            "A timeout does not prove that an ICMP message was suppressed.",
            "Sparse TTL sampling does not reveal an exact route or DPI location.",
        ],
    }


def run(target_ip: str, samples: int = 1) -> dict:
    print("\n[*] Sampled TCP TTL Reachability")
    print(f"    Target  : {target_ip}:443")
    print(f"    TTLs    : {DEFAULT_TTLS}")
    print(f"    Samples : {samples}")
    print("    Note    : this is not a hop-by-hop traceroute\n")

    aggregate = {}
    raw_attempts = []
    for ttl in DEFAULT_TTLS:
        attempts = [probe_ttl(target_ip, 443, ttl) for _ in range(samples)]
        raw_attempts.extend(attempts)
        statuses = summarize_status([row["outcome"] for row in attempts])
        timings = summarize([row["connect_ms"] for row in attempts])
        aggregate[ttl] = {
            "dominant_outcome": statuses["dominant"],
            "outcome_breakdown": statuses["breakdown"],
            "connect_stats": timings,
        }
        print(f"    TTL {ttl:>3} -> {statuses['dominant'] or 'unknown':<16} {timings['median_ms'] or ''}")

    representative = [
        {"ttl": ttl, "outcome": row["dominant_outcome"]}
        for ttl, row in aggregate.items()
    ]
    analysis = analyze(representative)
    print(f"\n    Lowest sampled TTL connected : {analysis['min_ttl_to_connect']}")
    print("    Attribution                 : none")
    return {"samples_by_ttl": aggregate, "analysis": analysis, "attempts": raw_attempts}
