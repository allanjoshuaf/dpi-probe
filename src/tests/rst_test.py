import socket
import time

def test_rst_origin(target_ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """
    Try to determine if a TCP RST comes from the real server
    or from a middlebox by comparing TTL and timing anomalies.
    
    A RST from a middlebox arrives faster than one from the real server
    and often has a different TTL signature.
    """
    result = {
        "target": target_ip,
        "port": port,
        "status": None,
        "rtt_ms": None,
        "rst_timing_ms": None,
        "verdict": None,
        "note": None,
    }

    print(f"\n[*] RST Origin Fingerprinting")
    print(f"    Target : {target_ip}:{port}\n")

    # Step 1 - measure legitimate connection RTT as baseline
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, port))
        baseline_rtt = round((time.time() - start) * 1000, 2)
        s.close()
        result["rtt_ms"] = baseline_rtt
        print(f"    [+] Baseline RTT         : {baseline_rtt}ms")
    except Exception as e:
        result["status"] = "error"
        result["note"] = str(e)
        print(f"    [!] Baseline failed : {e}")
        return result

    # Step 2 - send an illegal HTTP request to provoke a RST
    # and measure how fast it arrives
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))

        # Send a malformed HTTP/1.0 request with a blocked SNI keyword in the Host
        # This should provoke a RST from DPI faster than from the real server
        s.send(b"GET / HTTP/1.0\r\nHost: instagram.com\r\nX-Probe: dpi-probe\r\n\r\n")

        start = time.time()
        try:
            response = s.recv(4096)
            rst_timing = round((time.time() - start) * 1000, 2)
            result["rst_timing_ms"] = rst_timing

            if len(response) == 0:
                result["status"] = "rst"
                print(f"    [+] RST received         : {rst_timing}ms")
            else:
                result["status"] = "response"
                print(f"    [+] Response received    : {rst_timing}ms ({len(response)} bytes)")

        except socket.timeout:
            result["status"] = "timeout"
            print(f"    [!] Timeout waiting for RST")

        s.close()

    except ConnectionResetError:
        rst_timing = round((time.time() - start) * 1000, 2)
        result["status"] = "rst"
        result["rst_timing_ms"] = rst_timing
        print(f"    [+] RST received         : {rst_timing}ms")
    except Exception as e:
        result["status"] = "error"
        result["note"] = str(e)
        print(f"    [!] Error : {e}")

    # Step 3 - analyze timing
    if result["rtt_ms"] and result["rst_timing_ms"]:
        ratio = result["rst_timing_ms"] / result["rtt_ms"]

        if ratio < 0.5:
            result["verdict"] = "middlebox"
            result["note"] = f"RST arrived in {ratio:.2f}x baseline RTT - too fast to come from destination"
        elif ratio < 1.5:
            result["verdict"] = "ambiguous"
            result["note"] = f"RST timing close to baseline ({ratio:.2f}x) - could be either"
        else:
            result["verdict"] = "server"
            result["note"] = f"RST timing ({ratio:.2f}x baseline) consistent with real server response"

    print(f"\n[*] RST Analysis")
    print(f"    verdict  : {result['verdict']}")
    print(f"    note     : {result['note']}")

    return result

def run(target_ip: str, samples: int = 1):
    from src.stats import summarize

    print("\n[*] RST Origin Fingerprinting")
    print(f"    Target  : {target_ip}:443")
    print(f"    Samples : {samples}\n")

    baseline_rtts = []
    rst_rtts = []
    verdicts = []

    for i in range(samples):
        r = test_rst_origin(target_ip)
        baseline_rtts.append(r.get("rtt_ms"))
        rst_rtts.append(r.get("rst_timing_ms"))
        verdicts.append(r.get("verdict"))

    baseline_stats = summarize(baseline_rtts)
    rst_stats = summarize(rst_rtts)
    verdict_counts = {}
    for v in verdicts:
        if v:
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
    dominant_verdict = max(verdict_counts, key=verdict_counts.get) if verdict_counts else "unknown"

    ratio = None
    if baseline_stats["median_ms"] and rst_stats["median_ms"]:
        ratio = round(rst_stats["median_ms"] / baseline_stats["median_ms"], 2)

    observation = "unknown"
    if ratio:
        if ratio < 0.5:
            observation = "consistent_with_rst_injection"
        elif ratio < 1.5:
            observation = "ambiguous"
        else:
            observation = "consistent_with_server_rst"

    print(f"    Baseline RTT  : {baseline_stats['median_ms']}ms median")
    print(f"    RST timing    : {rst_stats['median_ms']}ms median")
    print(f"    Ratio         : {ratio}x")
    print(f"    Verdict       : {dominant_verdict} ({int(verdict_counts.get(dominant_verdict, 0) / samples * 100)}% of runs)")
    print(f"    Observation   : {observation}")

    return {
        "target": target_ip,
        "samples": samples,
        "baseline_rtt": baseline_stats,
        "rst_timing": rst_stats,
        "ratio": ratio,
        "dominant_verdict": dominant_verdict,
        "verdict_breakdown": {k: round(v / samples, 2) for k, v in verdict_counts.items()},
        "observation": observation,
    }