import socket
import struct
import time

def test_ttl_hop(target_ip: str, port: int = 443, ttl_values: list = None) -> list:
    """
    Send TCP SYN packets with increasing TTL values.
    If a middlebox intercepts, it will respond before the real server.
    """
    if ttl_values is None:
        ttl_values = [1, 2, 3, 5, 8, 13, 21, 64]

    results = []

    print("\n[*] TTL Hop Test")
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
            print(f"    TTL {ttl:>3} → connected    RTT {rtt}ms")

        except socket.timeout:
            result["status"] = "timeout"
            result["note"] = "dropped in transit"
            print(f"    TTL {ttl:>3} → timeout      dropped in transit")

        except OSError as e:
            msg = str(e).lower()
            if "ttl" in msg or "time" in msg or "expired" in msg:
                result["status"] = "ttl_expired"
                result["note"] = "ICMP TTL exceeded — hop detected"
                print(f"    TTL {ttl:>3} → ttl_expired  hop detected")
            else:
                result["status"] = "error"
                result["note"] = str(e)
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
        analysis["reason"] = "Connection established at very low TTL — possible local middlebox"

    if timeouts and connected:
        gap_ttls = [r["ttl"] for r in timeouts if r["ttl"] < connected[0]["ttl"]]
        if gap_ttls:
            analysis["suspicious"] = True
            analysis["reason"] = f"Silent drop at TTL {gap_ttls} before connection — middlebox interference"

    return analysis

def run(target_ip: str):
    results = test_ttl_hop(target_ip)
    analysis = analyze(results)

    print("\n[*] TTL Analysis")
    for k, v in analysis.items():
        print(f"    {k:<25} : {v}")

    return {"hops": results, "analysis": analysis}