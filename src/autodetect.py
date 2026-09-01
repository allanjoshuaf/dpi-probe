import socket
from src import config as cfg

def quick_sni_check(target_ip: str, sni: str, timeout: float = 3.0) -> str:
    try:
        from src.probes.sni_test import build_tls_client_hello
        with socket.create_connection((target_ip, 443), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_tls_client_hello(sni))
            try:
                response = s.recv(4096)
            except socket.timeout:
                return "no_response_before_timeout"
            if len(response) == 0:
                return "connection_closed_no_data"
            elif response[0] == 0x15:
                return "tls_alert"
            elif response[0] == 0x16:
                return "ok"
            return "unknown"
    except ConnectionResetError:
        return "rst"
    except Exception:
        return "error"

def run(config: dict = None) -> dict:
    conf = config or cfg.load()
    targets = conf.get("targets", [])
    blocked = conf["domains"]["blocked"]
    clean   = conf["domains"]["clean"]

    print("\n[*] Checking for content-dependent network behavior...")
    print(f"    Testing {len(targets)} targets\n")

    signals = []
    details = []

    for t in targets:
        ip   = t["ip"]
        name = t["name"]
        print(f"    [{name} - {ip}]")

        drops = 0
        for domain in blocked:
            if quick_sni_check(ip, domain) in {"no_response_before_timeout", "connection_closed_no_data"}:
                drops += 1

        clean_ok = 0
        for domain in clean:
            if quick_sni_check(ip, domain) in ["tls_alert", "ok"]:
                clean_ok += 1

        sni_signal = drops >= 2 and clean_ok >= 2
        print(f"      No response    : {drops}/{len(blocked)} suspect-label hostnames")
        print(f"      TLS response   : {clean_ok}/{len(clean)} comparison hostnames")

        target_signal = sni_signal
        signals.append(target_signal)
        details.append({
            "target": ip,
            "name": name,
            "sni_drops": drops,
            "clean_ok": clean_ok,
            "content_dependent_signal": target_signal,
        })

        print(f"      Result         : {'content-dependent behavior' if target_signal else 'no differential observed'}\n")

    triggered = sum(signals)
    assessment = "content_dependent_behavior_observed" if triggered >= 2 else "inconclusive"

    verdict = {
        "dpi_detected": None,
        "assessment": assessment,
        "targets_triggered": triggered,
        "targets_tested": len(targets),
        "confidence": "moderate" if triggered >= 2 else "low",
        "details": details,
    }

    print("=" * 50)
    if triggered >= 2:
        print(f"  Content-dependent behavior observed on {triggered}/{len(targets)} targets")
        print(f"     Confidence : {verdict['confidence'].upper()}")
    else:
        print(f"  Inconclusive ({triggered}/{len(targets)} targets triggered)")
    print("  Attribution requires a controlled endpoint or dual-vantage capture.")
    print("=" * 50)

    return verdict
