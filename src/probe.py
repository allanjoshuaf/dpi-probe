import socket
import time
from src.tests import sni_test
from src.tests import ttl_test
from src.tests import rst_test
from src.tests import malformed_tls_test
from src import report
from src import config as cfg
from src.tests import ip_block_test
from src.tests import http_host_test
from src import correlator
from src.tests import dns_test

class Probe:
    def __init__(self, target, samples=1, config=None, profile=None, pcap=False, pcap_interface=None):
        self.target = target
        self.samples = samples
        self.config = config or cfg.load()
        self.profile = profile
        self.pcap = pcap
        self.pcap_interface = pcap_interface
        self.results = {}

    def test_tcp_rst(self):
        """Check if RST comes from target or a middlebox"""
        print("[*] Testing TCP RST behavior...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            start = time.time()
            s.connect((self.target, 443))
            rtt = round((time.time() - start) * 1000, 2)
            s.close()
            self.results["tcp_443"] = {"status": "open", "rtt_ms": rtt}
            print(f"    [+] Port 443 open - RTT {rtt}ms")
        except socket.timeout:
            self.results["tcp_443"] = {"status": "timeout"}
            print("    [!] Timeout - possible silent drop by DPI")
        except ConnectionRefusedError:
            self.results["tcp_443"] = {"status": "refused"}
            print("    [-] Connection refused")

    def test_plaintext_http(self):
        """Send plain HTTP request and check for injection or redirect"""
        print("[*] Testing plain HTTP...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, 80))
            s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            response = s.recv(1024).decode(errors="ignore")
            s.close()
            if "302" in response or "301" in response:
                self.results["http"] = {"status": "redirect"}
                print("    [!] Redirect detected - HTTP behavior differs from baseline")
            elif "reset" in response.lower() or len(response) == 0:
                self.results["http"] = {"status": "blocked"}
                print("    [!] Empty response - possible block")
            else:
                self.results["http"] = {"status": "ok"}
                print("    [+] HTTP response looks normal")
        except Exception as e:
            self.results["http"] = {"status": "error", "detail": str(e)}
            print(f"    [!] Error: {e}")

    def test_sni(self):
        """Test SNI-based filtering"""
        results = sni_test.run(self.target, self.samples, self.config)
        self.results["sni"] = results

    def test_ttl(self):
        """TTL hop analysis to detect middleboxes"""
        results = ttl_test.run(self.target, self.samples)
        self.results["ttl"] = results

    def test_rst(self):
        """RST origin fingerprinting"""
        results = rst_test.run(self.target, self.samples)
        self.results["rst"] = results        

    def test_malformed_tls(self):
        """Malformed TLS ClientHello fingerprinting"""
        results = malformed_tls_test.run(self.target, self.samples)
        self.results["malformed_tls"] = results

    def test_ip_blocking(self):
        """IP-based blocking classification"""
        results = ip_block_test.run(self.config)
        self.results["ip_blocking"] = results

    def test_http_host(self):
        """HTTP Host header filtering detection"""
        results = http_host_test.run(self.config)
        self.results["http_host"] = results

    def test_dns(self):
        """DNS poisoning detection"""
        results = dns_test.run(self.config)
        self.results["dns"] = results

    def run(self):
        if self.pcap:
            from src import pcap as pcap_module
            import os
            import subprocess
            os.makedirs("reports", exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            pcap_path = f"reports/capture_{self.target.replace('.', '_')}_{ts}.pcapng"
            tshark = pcap_module.find_tshark()
            interface = self.pcap_interface or "5"
            cmd = [
                tshark,
                "-i", interface,
                "-f", f"host {self.target} and port 443",
                "-w", pcap_path,
                "-q",
            ]
            print(f"\n[*] PCAP capture started - interface {interface}")
            proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

        self.test_tcp_rst()
        self.test_plaintext_http()
        self.test_sni()
        self.test_ttl()
        self.test_rst()
        self.test_malformed_tls()
        self.test_ip_blocking()
        self.test_http_host()
        self.test_dns()

        if self.pcap:
            proc.terminate()
            proc.wait()
            size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
            print(f"    [+] Capture stopped - {size} bytes saved")
            analysis = pcap_module.analyze(pcap_path, self.target)
            self.results["pcap"] = {"pcap_path": pcap_path, "analysis": analysis}

        if self.pcap and self.results.get("pcap"):
            sni_attempts = []
            for r in self.results.get("sni", []):
                for attempt in r.get("attempts", []):
                    if attempt.get("start_time_epoch"):
                        sni_attempts.append(attempt)
            
            pcap_analysis = self.results["pcap"].get("analysis", {})
            if pcap_analysis and sni_attempts:
                correlation = correlator.correlate(sni_attempts, pcap_analysis)
                correlator.print_summary(correlation)
                self.results["pcap_correlation"] = correlation        

        r = report.generate(self.target, self.results, self.profile, self.samples)
        report.print_summary(r)
        path = report.save(r)
        print(f"\n  Report saved → {path}")
