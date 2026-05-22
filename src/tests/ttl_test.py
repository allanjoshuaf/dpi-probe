import socket
import struct
import time

def test_ttl_hop(target_ip: str, port: int = 443, ttl_values: list = None, silent: bool = False) -> list:
    """
    Send TCP SYN packets with increasing TTL values.
    If a middlebox intercepts, it will respond before the real server.
    """
    if ttl_values is None:
        ttl_values = [1, 2, 3, 5, 8, 13, 21, 64]

    results = []

    if not silent:
        print(f"\n[*] TTL Hop Test")
        print(f"    Target : {target_ip}:{port}\n")

    for ttl in ttl_values:
        result = {
            "ttl": ttl,
            "status": None,
            "rtt_ms": None,
            "note": None,
        }

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.settimeout(2)

            start = time.time()
            s.connect((target_ip, port))
            rtt = round((time.time() - start) * 1000, 2)
            s.close()

            result["status"] = "connected"
            result["rtt_ms"] = rtt
            result["note"] = "reached destination"
            if not silent:
                print(f"    TTL {ttl:>3} → connected    RTT {rtt}ms")

        except socket.timeout:
            result["status"] = "timeout"
            result["note"] = "dropped in transit"
            if not silent:
                print(f"    TTL {ttl:>3} → timeout      dropped in transit")

        except OSError as e:
            msg = str(e).lower()
            if "ttl" in msg or "time" in msg or "expired" in msg:
                result["status"] = "ttl_expired"
                result["note"] = "ICMP TTL exceeded - hop detected"
                if not silent:
                    print(f"    TTL {ttl:>3} → ttl_expired  hop detected")
            else:
                result["status"] = "error"
                result["note"] = str(e)
                if not silent:
                    print(f"    TTL {ttl:>3} → error        {e}")

        results.append(result)

    return results

def analyze(results: list) -> dict:
    """Look for anomalies that suggest a middlebox"""
    connected = [r for r in results if r["status"] == "connected"]
    timeouts  = [r for r in results if r["status"] == "timeout"]
    expired   = [r for r in results if r["status"] == "ttl_expired"]

    analysis = {
        "min_ttl_to_connect": connected[0]["ttl"] if connected else None,
        "hops_detected": len(expired),
        "suspicious": False,
        "reason": None,
    }

    if connected and connected[0]["ttl"] <= 3:
        analysis["suspicious"] = True
        analysis["reason"] = "Connection established at very low TTL - possible local middlebox"

    if timeouts and connected:
        gap_ttls = [r["ttl"] for r in timeouts if r["ttl"] < connected[0]["ttl"]]
        if gap_ttls:
            analysis["suspicious"] = True
            analysis["reason"] = f"Silent drop at TTL {gap_ttls} before connection - middlebox interference"

    return analysis

def run(target_ip: str, samples: int = 1):
    from src.stats import summarize

    print("\n[*] TTL Hop Test")
    print(f"    Target  : {target_ip}:443")
    print(f"    Samples : {samples}\n")

    ttl_values = [1, 2, 3, 5, 8, 13, 21, 64]
    ttl_results = {}

    for ttl in ttl_values:
        rtts = []
        statuses = []

        for _ in range(samples):
            r = test_ttl_hop(target_ip, ttl_values=[ttl], silent=True)
            if r:
                rtts.append(r[0]["rtt_ms"])
                statuses.append(r[0]["status"])

        stats = summarize(rtts)
        status_counts = {}
        for s in statuses:
            if s:
                status_counts[s] = status_counts.get(s, 0) + 1
        dominant = max(status_counts, key=status_counts.get) if status_counts else "unknown"

        ttl_results[ttl] = {
            "dominant_status": dominant,
            "status_breakdown": {k: round(v / samples, 2) for k, v in status_counts.items()},
            "rtt_stats": stats,
        }

        if dominant == "connected":
            print(f"    TTL {ttl:>3} → connected    {stats['median_ms']}ms median")
        else:
            print(f"    TTL {ttl:>3} → {dominant:<12} dropped in transit")

    # Analysis
    connected_ttls = [ttl for ttl, r in ttl_results.items() if r["dominant_status"] == "connected"]
    timeout_ttls   = [ttl for ttl, r in ttl_results.items() if r["dominant_status"] == "timeout"]

    min_ttl = min(connected_ttls) if connected_ttls else None
    suspicious = bool(timeout_ttls and connected_ttls)

    observation = "consistent_with_icmp_suppression" if suspicious else "no_ttl_anomaly"

    analysis = {
        "min_ttl_to_connect": min_ttl,
        "silent_ttls": timeout_ttls,
        "suspicious": suspicious,
        "observation": observation,
    }

    print(f"\n[*] TTL Analysis")
    print(f"    min_ttl_to_connect : {min_ttl}")
    print(f"    silent_ttls        : {timeout_ttls}")
    print(f"    observation        : {observation}")

    return {"hops": ttl_results, "analysis": analysis}