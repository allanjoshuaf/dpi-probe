import socket
import time

PROBE_TARGETS = [
    {"ip": "1.1.1.1",  "name": "Cloudflare DNS"},
    {"ip": "8.8.8.8",  "name": "Google DNS"},
    {"ip": "9.9.9.9",  "name": "Quad9 DNS"},
]

CANARY_DOMAINS = {
    "blocked": ["instagram.com", "facebook.com", "twitter.com"],
    "clean":   ["google.com", "github.com", "cloudflare.com"],
}

def quick_sni_check(target_ip: str, sni: str, timeout: float = 3.0) -> str:
    """Returns: ok | silent_drop | rst | error"""
    try:
        from src.tests.sni_test import build_tls_client_hello
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        s.send(build_tls_client_hello(sni))
        try:
            response = s.recv(4096)
            s.close()
            if len(response) == 0:
                return "silent_drop"
            elif response[0] == 0x15:
                return "tls_alert"
            elif response[0] == 0x16:
                return "ok"
            return "unknown"
        except socket.timeout:
            return "silent_drop"
    except ConnectionResetError:
        return "rst"
    except Exception:
        return "error"

def quick_rst_check(target_ip: str, timeout: float = 3.0) -> dict:
    """Measure baseline RTT vs response RTT to detect middlebox"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, 443))
        baseline = round((time.time() - start) * 1000, 2)
        s.close()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        s.send(b"GET / HTTP/1.0\r\nHost: instagram.com\r\n\r\n")
        start = time.time()
        try:
            s.recv(4096)
            response_time = round((time.time() - start) * 1000, 2)
        except socket.timeout:
            response_time = None
        s.close()

        if response_time and baseline:
            ratio = response_time / baseline
            return {"baseline": baseline, "response": response_time, "ratio": ratio}
        return {"baseline": baseline, "response": None, "ratio": None}
    except Exception:
        return {"baseline": None, "response": None, "ratio": None}

def run() -> dict:
    print("\n[*] Auto-detecting local DPI presence...")
    print(f"    Testing {len(PROBE_TARGETS)} targets\n")

    signals = []
    details = []

    for t in PROBE_TARGETS:
        ip   = t["ip"]
        name = t["name"]
        print(f"    [{name} — {ip}]")

        # SNI check
        drops = 0
        for domain in CANARY_DOMAINS["blocked"]:
            result = quick_sni_check(ip, domain)
            if result == "silent_drop":
                drops += 1

        clean_ok = 0
        for domain in CANARY_DOMAINS["clean"]:
            result = quick_sni_check(ip, domain)
            if result in ["tls_alert", "ok"]:
                clean_ok += 1

        sni_signal = drops >= 2 and clean_ok >= 2
        print(f"      SNI drops      : {drops}/{len(CANARY_DOMAINS['blocked'])} blocked domains")
        print(f"      SNI clean      : {clean_ok}/{len(CANARY_DOMAINS['clean'])} clean domains reachable")

        # RST timing check
        rst = quick_rst_check(ip)
        rst_signal = False
        if rst["ratio"] and rst["ratio"] < 0.5:
            rst_signal = True
        print(f"      RST ratio      : {rst['ratio']}x baseline" if rst["ratio"] else "      RST ratio      : N/A")

        target_signal = sni_signal or rst_signal
        signals.append(target_signal)
        details.append({
            "target": ip,
            "name": name,
            "sni_drops": drops,
            "clean_ok": clean_ok,
            "rst_ratio": rst["ratio"],
            "dpi_signal": target_signal,
        })

        status = "⚠ DPI signal" if target_signal else "✓ clean"
        print(f"      Result         : {status}\n")

    # Verdict
    triggered = sum(signals)
    dpi_detected = triggered >= 2

    verdict = {
        "dpi_detected": dpi_detected,
        "targets_triggered": triggered,
        "targets_tested": len(PROBE_TARGETS),
        "confidence": "high" if triggered == len(PROBE_TARGETS) else "medium" if triggered >= 2 else "low",
        "details": details,
    }

    print("=" * 50)
    if dpi_detected:
        print(f"  ⚠  DPI DETECTED — {triggered}/{len(PROBE_TARGETS)} targets triggered")
        print(f"     Confidence : {verdict['confidence'].upper()}")
    else:
        print(f"  ✓  No DPI detected ({triggered}/{len(PROBE_TARGETS)} targets triggered)")
    print("=" * 50)

    return verdict