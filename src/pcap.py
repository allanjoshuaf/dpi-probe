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
        "-f", f"host {target_ip}",
        "-w", output_path,
        "-a", f"duration:{duration}",
        "-q",
    ]

    result = {"output_path": output_path, "target_ip": target_ip, "duration": duration}

    try:
        print(f"\n[*] PCAP capture starting - {duration}s on interface {interface}")
        print(f"    Filter : host {target_ip}")
        print(f"    Output : {output_path}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        result["returncode"] = proc.returncode
        result["stderr"] = proc.stderr.strip()

        if proc.returncode == 0:
            size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            result["size_bytes"] = size
            result["status"] = "ok"
            print(f"    [+] Capture complete - {size} bytes saved")
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
    tshark = find_tshark()
    if not tshark:
        return {"error": "tshark not found"}
    if not os.path.exists(pcap_path):
        return {"error": f"File not found: {pcap_path}"}

    print(f"\n[*] PCAP Analysis - {pcap_path}", flush=True)

    def run_tshark(filter_expr, fields, timeout=15):
        cmd = [tshark, "-n", "-r", pcap_path, "-T", "fields",
               "-Y", filter_expr] + fields
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                err = r.stderr.strip()
                if err:
                    print(f"    [!] tshark error for filter '{filter_expr}': {err}", flush=True)
            return [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
        except subprocess.TimeoutExpired:
            print(f"    [!] tshark timeout after {timeout}s for filter '{filter_expr}'", flush=True)
            return []
        except Exception:
            print(f"    [!] tshark failed for filter '{filter_expr}'", flush=True)
            return []

    # RST packets
    rst_lines = run_tshark(
        f"tcp.flags.reset == 1 and ip.addr == {target_ip}",
        [
            "-e", "frame.time_epoch",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.ttl",
            "-e", "tcp.stream",
        ]
    )
    rst_packets = []
    for line in rst_lines:
        parts = line.split("\t")
        if len(parts) >= 5:
            rst_packets.append({
                "time_epoch": parts[0],
                "time": parts[1],
                "src": parts[2],
                "ttl": parts[3],
                "tcp_stream": parts[4],
            })

    # Retransmissions
    retrans_lines = run_tshark(
        f"tcp.analysis.retransmission and ip.addr == {target_ip}",
        [
            "-e", "frame.time_epoch",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.ttl",
            "-e", "tcp.stream",
        ]
    )
    retransmissions = []
    for line in retrans_lines:
        parts = line.split("\t")
        if len(parts) >= 5:
            retransmissions.append({
                "time_epoch": parts[0],
                "time": parts[1],
                "src": parts[2],
                "ttl": parts[3],
                "tcp_stream": parts[4],
            })
    # TCP window size anomalies
    window_lines = run_tshark(
        f"tcp.flags.reset == 1 and ip.addr == {target_ip}",
        [
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "tcp.window_size",
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "ip.ttl",
        ]
    )

    rst_anomalies = []

    for line in window_lines:
        parts = line.split("\t")

        if len(parts) >= 6:
            rst_anomalies.append({
                "time": parts[0],
                "src": parts[1],
                "window": parts[2],
                "seq": parts[3],
                "ack": parts[4],
                "ttl": parts[5],
            })

    suspicious_rst = []

    for r in rst_anomalies:
        flags = []

        try:
            if int(r["window"]) == 0:
                flags.append("zero_window")
        except Exception:
            pass

        try:
            ttl = int(r["ttl"])

            if ttl < 50 and ttl != 64:
                flags.append("low_ttl")
        except Exception:
            pass

        if flags:
            r["flags"] = flags
            suspicious_rst.append(r)

    # Client -> Server TTL
    client_ttl_lines = run_tshark(
        f"tcp and ip.dst == {target_ip}",
        ["-e", "ip.ttl"]
    )

    server_ttl_lines = run_tshark(
        f"tcp and ip.src == {target_ip}",
        ["-e", "ip.ttl"]
    )

    client_ttls = []

    for line in client_ttl_lines:
        try:
            client_ttls.append(int(line.strip()))
        except Exception:
            pass

    # Server -> Client TTL
    server_ttl_lines = run_tshark(
        f"ip.src == {target_ip}",
        ["-e", "ip.ttl"]
    )

    server_ttls = []

    for line in server_ttl_lines:
        try:
            server_ttls.append(int(line.strip()))
        except Exception:
            pass
    
    rst_ttls = []
    rst_ttl_count = {}

    for r in rst_anomalies:
        try:
            ttl = int(r["ttl"])
            rst_ttls.append(ttl)
            rst_ttl_count[ttl] = rst_ttl_count.get(ttl, 0) + 1
        except Exception:
            pass

    ttl_breakdown = {
        "client_ttl": sorted(list(set(client_ttls))),
        "server_ttl": sorted(list(set(server_ttls))),
        "rst_ttl": sorted(list(set(rst_ttls))),
    }

    # RST sequence analysis
    rst_seqs = set()
    for r in rst_anomalies:
        seq = r.get("seq")
        if seq:
            rst_seqs.add(seq)

    # TTL values
    ttl_lines = run_tshark(
        f"ip.addr == {target_ip}",
        ["-e", "ip.ttl"]
    )
    ttls = []
    for line in ttl_lines:
        try:
            ttls.append(int(line.strip()))
        except Exception:
            pass
    ttls = list(set(ttls))

    # TLS alerts
    tls_lines = run_tshark(
        f"tls.record.content_type == 21 and ip.addr == {target_ip}",
        [
            "-e", "frame.time_epoch",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.ttl",
            "-e", "tcp.stream",
        ]
    )
    tls_alerts = []
    for line in tls_lines:
        parts = line.split("\t")
        if len(parts) >= 5:
            tls_alerts.append({
                "time_epoch": parts[0],
                "time": parts[1],
                "src": parts[2],
                "ttl": parts[3],
                "tcp_stream": parts[4],
            })
    # TLS ClientHello - SNI and version fingerprinting
    hello_lines = run_tshark(
        f"tls.handshake.type == 1 and ip.addr == {target_ip}",
        ["-e", "frame.time_epoch",
         "-e", "frame.time_relative",
         "-e", "ip.src",
         "-e", "tcp.stream",
         "-e", "tls.handshake.extensions_server_name",
         "-e", "tls.handshake.version",
         "-e", "ip.ttl"]
    )
    client_hellos = []
    for line in hello_lines:
        parts = line.split("\t")
        if len(parts) >= 7:
            client_hellos.append({
                "time_epoch": parts[0],
                "time": parts[1],
                "src": parts[2],
                "tcp_stream": parts[3],
                "sni": parts[4],
                "tls_version": parts[5],
                "ttl": parts[6],
            })

    # Packet size distribution
    size_lines = run_tshark(
        f"ip.addr == {target_ip}",
        ["-e", "frame.len"]
    )
    sizes = []
    for line in size_lines:
        try:
            sizes.append(int(line.strip()))
        except Exception:
            pass

    size_stats = {}
    if sizes:
        size_stats = {
            "min": min(sizes),
            "max": max(sizes),
            "avg": round(sum(sizes) / len(sizes), 1),
            "total_bytes": sum(sizes),
        }

    # Inter-packet timing
    timing_lines = run_tshark(
        f"ip.addr == {target_ip}",
        ["-e", "frame.time_delta"]
    )
    deltas = []
    for line in timing_lines:
        try:
            deltas.append(float(line.strip()))
        except Exception:
            pass

    timing_stats = {}
    if deltas:
        deltas_ms = [round(d * 1000, 2) for d in deltas]
        timing_stats = {
            "min_ms": min(deltas_ms),
            "max_ms": max(deltas_ms),
            "avg_ms": round(sum(deltas_ms) / len(deltas_ms), 2),
        }
    
    # Total packets
    total_lines = run_tshark(
        f"ip.addr == {target_ip}",
        ["-e", "frame.number"]
    )

    analysis = {
        "target_ip": target_ip,
        "client_hellos": len(client_hellos),
        "client_hello_details": client_hellos,
        "rst_anomalies": len(rst_anomalies),
        "suspicious_rst": suspicious_rst[:5],
        "unique_rst_seqs": len(rst_seqs),
        "ttl_breakdown": ttl_breakdown,
        "rst_ttl_count": rst_ttl_count,
        "packet_sizes": size_stats,
        "timing": timing_stats,
        "total_packets": len(total_lines),
        "rst_packets": len(rst_packets),
        "rst_details": rst_packets,
        "tls_alerts": len(tls_alerts),
        "tls_alert_details": tls_alerts,
        "retransmissions": len(retransmissions),
        "retransmission_details": retransmissions,
        "ttl_values": ttls,
        "ttl_min": min(ttls) if ttls else None,
        "ttl_max": max(ttls) if ttls else None,
    }

    print(f"    Total packets     : {analysis['total_packets']}", flush=True)
    print(f"    RST packets       : {analysis['rst_packets']}", flush=True)
    print(f"    TLS alerts        : {analysis['tls_alerts']}", flush=True)
    print(f"    RST TTL count     : {rst_ttl_count}", flush=True)
    print(f"    Retransmissions   : {analysis['retransmissions']}", flush=True)
    print(f"    RST anomalies     : {analysis['rst_anomalies']}", flush=True)
    print(f"    Unique RST seqs   : {analysis['unique_rst_seqs']}", flush=True)
    print(f"    TTL breakdown     : client={ttl_breakdown['client_ttl']} server={ttl_breakdown['server_ttl']} rst={ttl_breakdown['rst_ttl']}", flush=True)
    print(f"    TTL values seen   : {analysis['ttl_values']}", flush=True)
    print(f"    ClientHellos      : {analysis['client_hellos']}", flush=True)
    if client_hellos:
        print(f"\n    ClientHello SNI details (first 3):", flush=True)
        for h in client_hellos[:3]:
            print(f"      t={h['time']}s sni={h['sni']} tls={h['tls_version']} ttl={h['ttl']}", flush=True)
    if size_stats:
        print(f"\n    Packet sizes      : min={size_stats['min']}B avg={size_stats['avg']}B max={size_stats['max']}B", flush=True)
    if timing_stats:
        print(f"    Inter-pkt timing  : min={timing_stats['min_ms']}ms avg={timing_stats['avg_ms']}ms max={timing_stats['max_ms']}ms", flush=True)

    if rst_packets:
        print(f"\n    RST details (first 3):", flush=True)
        for r in rst_packets[:3]:
            print(f"      t={r['time']}s src={r['src']} ttl={r['ttl']}", flush=True)

    if tls_alerts:
        print(f"\n    TLS alert details (first 3):", flush=True)
        for a in tls_alerts[:3]:
            print(f"      t={a['time']}s src={a['src']} ttl={a['ttl']}", flush=True)

    return analysis

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
