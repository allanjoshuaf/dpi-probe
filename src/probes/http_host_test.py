import socket
import time

def test_http_host(target_ip: str, host: str, port: int = 80, timeout: float = 4.0) -> dict:
    """
    Send plain HTTP request with specific Host header.
    Check if response differs based on Host value.
    """
    result = {
        "host": host,
        "status": None,
        "response_code": None,
        "rtt_ms": None,
        "note": None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, port))
        rtt = round((time.time() - start) * 1000, 2)
        result["rtt_ms"] = rtt

        request = f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.send(request.encode())

        try:
            response = s.recv(4096).decode(errors="ignore")
            s.close()

            if len(response) == 0:
                result["status"] = "connection_closed_no_data"
                result["note"] = "Peer closed without application data"
            elif response.startswith("HTTP/"):
                first_line = response.split("\r\n")[0]
                code = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "unknown"
                result["status"] = "response"
                result["response_code"] = code
                result["note"] = first_line
            else:
                result["status"] = "unexpected"
                result["note"] = response[:80]

        except socket.timeout:
            result["status"] = "no_response_before_timeout"
            result["note"] = "No response before timeout after connect"

    except socket.timeout:
        result["status"] = "timeout"
        result["note"] = "Connection timeout"
    except ConnectionResetError:
        result["status"] = "rst"
        result["note"] = "TCP RST received"
    except Exception as e:
        result["status"] = "error"
        result["note"] = str(e)

    return result

def classify(host: str, result: dict, clean_codes: list) -> str:
    """Describe the observed outcome without attributing it to a filter."""
    status = result.get("status")
    code = result.get("response_code")

    if status in {"no_response_before_timeout", "connection_closed_no_data"}:
        return "host_dependent_no_response"
    elif status == "rst":
        return "host_dependent_reset"
    elif status == "response" and code in clean_codes:
        return "no_filtering"
    elif status == "response":
        return f"response_{code}"
    elif status == "timeout":
        return "timeout"
    else:
        return "inconclusive"

def run(config: dict, target_ip: str = None) -> list:
    targets = [t["ip"] for t in config.get("targets", [])]
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    # Use first target IP for HTTP test
    target_ip = target_ip or (targets[0] if targets else "1.1.1.1")

    print("\n[*] HTTP Host Header Filtering Test")
    print(f"    Target IP : {target_ip}:80")
    print(f"    Testing {len(blocked + clean)} Host headers\n")

    results = []
    clean_responses = []

    # First pass - establish clean baseline response codes
    for host in clean:
        r = test_http_host(target_ip, host)
        if r["response_code"]:
            clean_responses.append(r["response_code"])

    clean_codes = list(set(clean_responses)) if clean_responses else ["200", "301", "302", "400"]

    # Second pass - test all domains
    for host in clean + blocked:
        category = "clean" if host in clean else "blocked"
        r = test_http_host(target_ip, host)
        classification = classify(host, r, clean_codes)

        indicator = "✓" if classification == "no_filtering" else \
                    "⚠" if classification in ["host_dependent_no_response", "host_dependent_reset"] else "?"

        print(f"    [{indicator}] {host:<25} → {classification:<20} {r['note'] or ''}")

        results.append({
            "host": host,
            "category": category,
            "classification": classification,
            "status": r["status"],
            "response_code": r["response_code"],
            "rtt_ms": r["rtt_ms"],
            "note": r["note"],
            "attribution": "on_path_or_destination",
            "limitation": "The destination is not a controlled virtual host for every Host value.",
        })

    return results
