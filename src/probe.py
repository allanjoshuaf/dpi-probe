import socket
import time
from src.tests import sni_test
from src.tests import ttl_test
from src.tests import rst_test
from src.tests import malformed_tls_test
from src import report
from src import config as cfg

class Probe:
    def __init__(self, target, samples=1):
        self.target = target
        self.samples = samples
        self.config = cfg.load()
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
                print("    [!] Redirect detected - possible DPI injection")
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

    def run(self):
        self.test_tcp_rst()
        self.test_plaintext_http()
        self.test_sni()
        self.test_ttl()
        self.test_rst()
        self.test_malformed_tls()
        r = report.generate(self.target, self.results)
        report.print_summary(r)
        path = report.save(r)
        print(f"\n  Report saved → {path}")