import socket
import time
from src.tests.sni_test import build_tls_client_hello

def test_ip_reachability(target_ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Test if a target IP is reachable on port 443"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, port))
        rtt = round((time.time() - start) * 1000, 2)
        s.close()
        return {"status": "open", "rtt_ms": rtt}
    except socket.timeout:
        return {"status": "timeout", "rtt_ms": None}
    except ConnectionRefusedError:
        return {"status": "refused", "rtt_ms": None}
    except Exception as e:
        return {"status": "error", "rtt_ms": None, "detail": str(e)}

def test_sni_across_ips(sni: str, target_ips: list, timeout: float = 4.0) -> dict:
    """
    Test the same SNI across multiple destination IPs.
    If behavior differs per IP, suggests SNI+IP correlation.
    If behavior is the same everywhere, suggests pure SNI filtering.
    """
    results = {}

    for ip in target_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, 443))
            s.send(build_tls_client_hello(sni))
            try:
                response = s.recv(4096)
                if len(response) == 0:
                    status = "silent_drop"
                elif response[0] == 0x15:
                    status = "tls_alert"
                elif response[0] == 0x16:
                    status = "server_hello"
                else:
                    status = f"unknown_{hex(response[0])}"
            except socket.timeout:
                status = "silent_drop"
            s.close()
        except socket.timeout:
            status = "timeout"
        except ConnectionResetError:
            status = "rst"
        except Exception:
            status = "error"

        results[ip] = status

    return results

def classify(sni: str, results: dict) -> dict:
    """
    Classify the blocking type based on behavior across IPs.
    """
    statuses = list(results.values())
    unique = set(statuses)

    if all(s == "silent_drop" for s in statuses):
        classification = "pure_sni_filtering"
        note = "Domain dropped across all destination IPs — consistent with SNI-based filtering"
    elif all(s in ["tls_alert", "server_hello"] for s in statuses):
        classification = "no_blocking"
        note = "Domain passes on all destination IPs"
    elif "silent_drop" in statuses and any(s in ["tls_alert", "server_hello"] for s in statuses):
        classification = "sni_ip_correlation"
        note = "Domain blocked on some IPs but not others — consistent with SNI+IP correlation"
    else:
        classification = "inconclusive"
        note = f"Mixed results: {dict(zip(results.keys(), statuses))}"

    return {
        "sni": sni,
        "classification": classification,
        "note": note,
        "per_ip": results,
    }

def run(config: dict) -> list:
    targets = [t["ip"] for t in config.get("targets", [])]
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    print("\n[*] IP-Based Blocking Classification")
    print(f"    Testing {len(blocked + clean)} domains across {len(targets)} IPs\n")

    results = []

    for sni in clean + blocked:
        category = "clean" if sni in clean else "blocked"
        per_ip = test_sni_across_ips(sni, targets)
        classification = classify(sni, per_ip)
        classification["category"] = category

        indicator = "✓" if classification["classification"] == "no_blocking" else \
                    "⚠" if classification["classification"] == "sni_ip_correlation" else \
                    "✗" if classification["classification"] == "pure_sni_filtering" else "?"

        print(f"    [{indicator}] {sni:<25} → {classification['classification']}")
        for ip, status in per_ip.items():
            print(f"         {ip:<15} {status}")

        results.append(classification)

    return results