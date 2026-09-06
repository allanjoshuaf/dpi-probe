import socket
import time
from src.probes import sni_test
from src.probes import ttl_test
from src.probes import rst_test
from src.probes import malformed_tls_test
from src import report
from src import config as cfg
from src.probes import ip_block_test
from src.probes import http_host_test
from src import correlator
from src.probes import dns_test
from src.probes import fragmentation_test
from src.probes import bypass_test
from src.probes import tls_fingerprint
from src.probes import tls_mutation_test
from src.probes import ech_test

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
        """Measure TCP reachability only; this does not identify reset origin."""
        print("[*] Testing TCP 443 reachability...")
        try:
            start = time.monotonic()
            with socket.create_connection((self.target, 443), timeout=3):
                rtt = round((time.monotonic() - start) * 1000, 2)
            self.results["tcp_443"] = {"status": "open", "rtt_ms": rtt}
            print(f"    [+] Port 443 open - RTT {rtt}ms")
        except socket.timeout:
            self.results["tcp_443"] = {"status": "timeout"}
            print("    [!] Connection did not complete before timeout")
        except ConnectionRefusedError:
            self.results["tcp_443"] = {"status": "refused"}
            print("    [-] Connection refused")

    def test_plaintext_http(self):
        """Observe the response to one plaintext HTTP request."""
        print("[*] Testing plain HTTP...")
        try:
            with socket.create_connection((self.target, 80), timeout=5) as s:
                s.settimeout(5)
                s.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                response = s.recv(1024).decode(errors="ignore")
            if "302" in response or "301" in response:
                self.results["http"] = {"status": "redirect"}
                print("    [*] Redirect response observed")
            elif len(response) == 0:
                self.results["http"] = {"status": "connection_closed_no_data"}
                print("    [*] Connection closed without response data")
            else:
                self.results["http"] = {"status": "ok"}
                print("    [+] HTTP response looks normal")
        except Exception as e:
            self.results["http"] = {"status": "error", "detail": str(e)}
            print(f"    [!] Error: {e}")

    def test_sni(self):
        """Measure crafted ClientHello outcomes by SNI value."""
        results = sni_test.run(self.target, self.samples, self.config)
        self.results["sni"] = results

    def test_ttl(self):
        """Sample TCP reachability at selected outgoing TTL values."""
        results = ttl_test.run(self.target, self.samples)
        self.results["ttl"] = results

    def test_rst(self):
        """Observe post-connect TCP outcomes; do not infer reset origin."""
        results = rst_test.run(self.target, self.samples)
        self.results["rst"] = results

    def test_malformed_tls(self):
        """Observe responses to malformed TLS ClientHello variants."""
        results = malformed_tls_test.run(self.target, self.samples)
        self.results["malformed_tls"] = results

    def test_ip_blocking(self):
        """Compare TLS outcomes across configured destination IPs."""
        results = ip_block_test.run(self.config)
        self.results["ip_blocking"] = results

    def test_http_host(self):
        """Compare plaintext HTTP outcomes by Host value."""
        results = http_host_test.run(self.config, target_ip=self.target)
        self.results["http_host"] = results

    def test_dns(self):
        """Compare resolver views without assuming poisoning."""
        results = dns_test.run(self.config)
        self.results["dns"] = results

    def test_fragmentation(self):
        """Compare application-level TCP write segmentation outcomes."""
        results = fragmentation_test.run(self.config, self.target)
        self.results["fragmentation"] = results

    def test_bypass(self):
        """Measure outcome changes after TLS record splitting and padding."""
        results = bypass_test.run(self.config, self.target)
        self.results["bypass"] = results

    def test_tls_fingerprint(self):
        """TLS JA3 Signature"""
        results = tls_fingerprint.run(self.config, self.target)
        self.results["tls_fingerprint"] = results

    def test_tls_mutation(self):
        """TLS JA3 Mutation Test"""
        results = tls_mutation_test.run(self.config, target_ips=[self.target], samples=self.samples)
        self.results["tls_mutation"] = results

    def test_ech(self):
        """Inspect ECH DNS publication; never imply a completed ECH handshake."""
        domains = self.config['domains']['clean'] + self.config['domains']['blocked']
        self.results['ech'] = [ech_test.run(domain) for domain in dict.fromkeys(domains)]

    def run(self):
        proc = None
        pcap_path = None
        pcap_module = None
        os = None
        subprocess = None

        if self.pcap:
            from src import pcap as pcap_module
            import os
            import subprocess
            os.makedirs("reports", exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            pcap_path = f"reports/capture_{self.target.replace('.', '_')}_{ts}.pcapng"
            tshark = pcap_module.find_tshark()
            if not tshark:
                raise RuntimeError('Requested capture requires TShark. Run the installer or --doctor; no probes were sent.')
            else:
                interface = self.pcap_interface or "1"
                cmd = [
                    tshark,
                    "-i", interface,
                    "-f", f"host {self.target} and port 443",
                    "-w", pcap_path,
                    "-q",
                ]
                print(f"\n[*] PCAP capture started - interface {interface}", flush=True)
                proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
                time.sleep(1.0)
                if proc.poll() is not None:
                    error = proc.stderr.read().strip() if proc.stderr else ""
                    self.results["pcap"] = {
                        "pcap_path": None,
                        "analysis": {"error": error or f"tshark exited with {proc.returncode}"},
                    }
                    print(f"[!] PCAP failed to start: {self.results['pcap']['analysis']['error']}")
                    if proc.stderr:
                        proc.stderr.close()
                    raise RuntimeError('Capture failed to start; check interface and privileges. No probes were sent.')

        try:
            tests = [
                ("tcp_443", self.test_tcp_rst),
                ("http", self.test_plaintext_http),
                ("sni", self.test_sni),
                ("ttl", self.test_ttl),
                ("rst", self.test_rst),
                ("malformed_tls", self.test_malformed_tls),
                ("ip_blocking", self.test_ip_blocking),
                ("http_host", self.test_http_host),
                ("dns", self.test_dns),
                ("fragmentation", self.test_fragmentation),
                ("bypass", self.test_bypass),
                ("tls_fingerprint", self.test_tls_fingerprint),
                ("tls_mutation", self.test_tls_mutation),
                ("ech", self.test_ech),
            ]
            for result_key, method in tests:
                try:
                    method()
                except Exception as exc:
                    self.results[result_key] = {
                        "status": "error",
                        "error_type": type(exc).__name__,
                        "detail": str(exc),
                    }
                    print(f"[!] {result_key} failed: {type(exc).__name__}: {exc}")
        finally:
            if self.pcap and proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()

                if proc.stderr:
                    proc.stderr.close()

                size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
                print(f"    [+] Capture stopped - {size} bytes saved", flush=True)

                if pcap_module is not None and pcap_path:
                    try:
                        analysis = pcap_module.analyze(pcap_path, self.target)
                    except Exception as exc:
                        analysis = {
                            "error": f"{type(exc).__name__}: {exc}",
                            "pcap_path": pcap_path,
                        }
                    self.results["pcap"] = {"pcap_path": pcap_path, "analysis": analysis}

        if self.pcap and self.results.get("pcap") and not self.results["pcap"].get("analysis", {}).get("error"):
            sni_attempts = []
            sni_rows = self.results.get("sni")
            for r in sni_rows if isinstance(sni_rows, list) else []:
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
