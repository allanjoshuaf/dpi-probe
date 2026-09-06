import socket
import time
from src.probes.sni_test import build_tls_client_hello

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
    This is a differential observation only: the IPs belong to different
    providers and do not form equivalent controlled endpoints.
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
                    status = "connection_closed_no_data"
                elif response[0] == 0x15:
                    status = "tls_alert"
                elif response[0] == 0x16:
                    status = "server_hello"
                else:
                    status = f"unknown_{hex(response[0])}"
            except socket.timeout:
                status = "no_response_before_timeout"
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

    no_response = {"no_response_before_timeout", "connection_closed_no_data", "silent_drop"}
    if all(s in no_response for s in statuses):
        classification = "uniform_no_response"
        note = "No response was observed for this ClientHello on any tested destination"
    elif all(s in ["tls_alert", "server_hello"] for s in statuses):
        classification = "uniform_response"
        note = "A TLS response was observed on all tested destinations"
    elif any(s in no_response for s in statuses) and any(s in ["tls_alert", "server_hello"] for s in statuses):
        classification = "destination_dependent"
        note = "The observed outcome changes with the destination IP"
    else:
        classification = "inconclusive"
        note = f"Mixed results: {dict(zip(results.keys(), statuses))}"

    return {
        "sni": sni,
        "classification": classification,
        "note": note,
        "per_ip": results,
        "attribution": "unresolved",
        "limitation": "Different providers may apply different server-side virtual-host policies.",
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

        indicator = "✓" if classification["classification"] == "uniform_response" else \
                    "⚠" if classification["classification"] == "destination_dependent" else \
                    "?"

        print(f"    [{indicator}] {sni:<25} → {classification['classification']}")
        for ip, status in per_ip.items():
            print(f"         {ip:<15} {status}")

        results.append(classification)

    return results
