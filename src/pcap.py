import subprocess
import threading
import time
import json
import os

TSHARK_PATH = "tshark"

def find_tshark():
    """Find tshark executable"""
    candidates = [
        "tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
    ]
    for c in candidates:
        try:
            result = subprocess.run(
                [c, "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return c
        except Exception:
            continue
    return None

def list_interfaces():
    """List available network interfaces"""
    tshark = find_tshark()
    if not tshark:
        return []
    try:
        result = subprocess.run(
            [tshark, "-D"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip().split("\n")
    except Exception:
        return []

def capture(target_ip: str, output_path: str, duration: int = 30, interface: str = None) -> dict:
    """
    Run a tshark capture filtered to target IP for duration seconds.
    Returns capture metadata.
    """
    tshark = find_tshark()
    if not tshark:
        return {"error": "tshark not found"}

    if not interface:
        interface = "1"  # default first interface

    cmd = [
        tshark,
        "-i", interface,
        "-f", f"host {target_ip} and port 443",
        "-w", output_path,
        "-a", f"duration:{duration}",
        "-q",
    ]

    result = {"output_path": output_path, "target_ip": target_ip, "duration": duration}

    try:
        print(f"\n[*] PCAP capture starting — {duration}s on interface {interface}")
        print(f"    Filter : host {target_ip} and port 443")
        print(f"    Output : {output_path}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        result["returncode"] = proc.returncode
        result["stderr"] = proc.stderr.strip()

        if proc.returncode == 0:
            size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            result["size_bytes"] = size
            result["status"] = "ok"
            print(f"    [+] Capture complete — {size} bytes saved")
        else:
            result["status"] = "error"
            print(f"    [!] Capture error: {proc.stderr.strip()}")

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)

    return result

def analyze(pcap_path: str, target_ip: str) -> dict:
    """
    Extract key fields from pcap using tshark JSON output.
    Focus on: TTL, TCP flags, RST packets, TLS alerts, retransmissions.
    """
    tshark = find_tshark()
    if not tshark:
        return {"error": "tshark not found"}

    if not os.path.exists(pcap_path):
        return {"error": f"File not found: {pcap_path}"}

    fields = [
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.ttl",
        "-e", "tcp.flags",
        "-e", "tcp.flags.reset",
        "-e", "tcp.flags.syn",
        "-e", "tcp.analysis.retransmission",
        "-e", "tls.record.content_type",
        "-e", "tls.handshake.type",
    ]

    cmd = [
        tshark,
        "-r", pcap_path,
        "-T", "json",
        "-Y", f"ip.addr == {target_ip}",
    ] + fields

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"error": result.stderr.strip()}

        packets = json.loads(result.stdout) if result.stdout.strip() else []

        rst_packets = []
        tls_alerts = []
        retransmissions = []
        ttls = []

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})

            ttl = layers.get("ip.ttl")
            if ttl:
                if isinstance(ttl, list):
                    ttls.extend([int(t) for t in ttl if t])
                else:
                    ttls.append(int(ttl))

            if layers.get("tcp.flags.reset") == "1":
                rst_packets.append({
                    "time": layers.get("frame.time_relative"),
                    "src": layers.get("ip.src"),
                    "ttl": layers.get("ip.ttl"),
                })

            if layers.get("tls.record.content_type") == "21":
                tls_alerts.append({
                    "time": layers.get("frame.time_relative"),
                    "src": layers.get("ip.src"),
                    "ttl": layers.get("ip.ttl"),
                })

            if layers.get("tcp.analysis.retransmission"):
                retransmissions.append(layers.get("frame.time_relative"))

        analysis = {
            "total_packets": len(packets),
            "rst_packets": len(rst_packets),
            "rst_details": rst_packets[:5],
            "tls_alerts": len(tls_alerts),
            "tls_alert_details": tls_alerts[:5],
            "retransmissions": len(retransmissions),
            "ttl_values": list(set(ttls)),
            "ttl_min": min(ttls) if ttls else None,
            "ttl_max": max(ttls) if ttls else None,
        }

        print(f"\n[*] PCAP Analysis — {pcap_path}")
        print(f"    Total packets     : {analysis['total_packets']}")
        print(f"    RST packets       : {analysis['rst_packets']}")
        print(f"    TLS alerts        : {analysis['tls_alerts']}")
        print(f"    Retransmissions   : {analysis['retransmissions']}")
        print(f"    TTL values seen   : {analysis['ttl_values']}")

        if rst_packets:
            print(f"\n    RST details:")
            for r in rst_packets[:3]:
                print(f"      t={r['time']}s src={r['src']} ttl={r['ttl']}")

        if tls_alerts:
            print(f"\n    TLS alert details:")
            for a in tls_alerts[:3]:
                print(f"      t={a['time']}s src={a['src']} desc={a['desc']} ttl={a['ttl']}")

        return analysis

    except json.JSONDecodeError:
        return {"error": "Failed to parse tshark JSON output"}
    except Exception as e:
        return {"error": str(e)}

def run(target_ip: str, output_dir: str = "reports", duration: int = 30, interface: str = None) -> dict:
    """
    Full PCAP workflow: capture then analyze.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(output_dir, f"capture_{target_ip.replace('.', '_')}_{ts}.pcapng")

    capture_result = capture(target_ip, pcap_path, duration, interface)

    if capture_result.get("status") != "ok":
        return {"capture": capture_result, "analysis": None}

    analysis = analyze(pcap_path, target_ip)

    return {
        "capture": capture_result,
        "analysis": analysis,
        "pcap_path": pcap_path,
    }