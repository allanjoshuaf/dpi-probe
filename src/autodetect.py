import socket
import time
from src import config as cfg

def quick_sni_check(target_ip: str, sni: str, timeout: float = 3.0) -> str:
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

def quick_rst_check(target_ip: str, blocked_domains: list, timeout: float = 3.0) -> dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((target_ip, 443))
        baseline = round((time.time() - start) * 1000, 2)
        s.close()

        test_domain = blocked_domains[0] if blocked_domains else "instagram.com"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, 443))
        s.send(f"GET / HTTP/1.0\r\nHost: {test_domain}\r\n\r\n".encode())
        start = time.time()
        try:
            s.recv(4096)
            response_time = round((time.time() - start) * 1000, 2)
        except socket.timeout:
            response_time = None
        s.close()

        if response_time and baseline:
            return {"baseline": baseline, "response": response_time, "ratio": response_time / baseline}
        return {"baseline": baseline, "response": None, "ratio": None}
    except Exception:
        return {"baseline": None, "response": None, "ratio": None}

def run(config: dict = None) -> dict:
    conf = config or cfg.load()
    targets = conf.get("targets", [])
    blocked = conf["domains"]["blocked"]
    clean   = conf["domains"]["clean"]

    print("\n[*] Auto-detecting local DPI presence...")
    print(f"    Testing {len(targets)} targets\n")

    signals = []
    details = []

    for t in targets:
        ip   = t["ip"]
        name = t["name"]
        print(f"    [{name} - {ip}]")

        drops = 0
        for domain in blocked:
            if quick_sni_check(ip, domain) == "silent_drop":
                drops += 1

        clean_ok = 0
        for domain in clean:
            if quick_sni_check(ip, domain) in ["tls_alert", "ok"]:
                clean_ok += 1

        sni_signal = drops >= 2 and clean_ok >= 2
        print(f"      SNI drops      : {drops}/{len(blocked)} blocked domains")
        print(f"      SNI clean      : {clean_ok}/{len(clean)} clean domains reachable")

        rst = quick_rst_check(ip, blocked)
        rst_signal = bool(rst["ratio"] and rst["ratio"] < 0.5)
        print(f"      RST ratio      : {round(rst['ratio'], 2)}x baseline" if rst["ratio"] else "      RST ratio      : N/A")

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

        print(f"      Result         : {'⚠ DPI signal' if target_signal else '✓ clean'}\n")

    triggered = sum(signals)
    dpi_detected = triggered >= 2

    verdict = {
        "dpi_detected": dpi_detected,
        "targets_triggered": triggered,
        "targets_tested": len(targets),
        "confidence": "high" if triggered == len(targets) else "medium" if triggered >= 2 else "low",
        "details": details,
    }

    print("=" * 50)
    if dpi_detected:
        print(f"  ⚠  DPI DETECTED - {triggered}/{len(targets)} targets triggered")
        print(f"     Confidence : {verdict['confidence'].upper()}")
    else:
        print(f"  ✓  No DPI detected ({triggered}/{len(targets)} targets triggered)")
    print("=" * 50)

    return verdict