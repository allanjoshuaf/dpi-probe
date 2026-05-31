import unittest

from src import correlator


class CorrelatorTest(unittest.TestCase):
    def test_correlates_sni_attempts_with_pcap_streams(self):
        sni_attempts = [
            {
                "sni": "instagram.com",
                "response_type": "silent_drop",
                "start_time_epoch": 100.0,
                "end_time_epoch": 101.0,
            },
            {
                "sni": "github.com",
                "response_type": "tls_alert",
                "start_time_epoch": 102.0,
                "end_time_epoch": 103.0,
            },
        ]
        pcap_analysis = {
            "target_ip": "1.1.1.1",
            "client_hello_details": [
                {"time_epoch": "100.2", "sni": "instagram.com", "tcp_stream": "1"},
                {"time_epoch": "110.2", "sni": "instagram.com", "tcp_stream": "7"},
                {"time_epoch": "102.2", "sni": "github.com", "tcp_stream": "2"},
            ],
            "tls_alert_details": [
                {"time_epoch": "102.4", "tcp_stream": "2"},
                {"time_epoch": "100.4", "tcp_stream": "99"},
            ],
            "rst_details": [
                {"time_epoch": "100.5", "tcp_stream": "99"},
            ],
            "retransmission_details": [
                {"time_epoch": "100.6", "tcp_stream": "1"},
            ],
        }

        result = correlator.correlate(sni_attempts, pcap_analysis)

        self.assertEqual(result["instagram.com"]["client_hellos"], 1)
        self.assertEqual(result["instagram.com"]["tls_alerts"], 0)
        self.assertEqual(result["instagram.com"]["rst_packets"], 0)
        self.assertEqual(result["instagram.com"]["retransmissions"], 1)
        self.assertEqual(result["instagram.com"]["tcp_streams"], ["1"])
        self.assertEqual(result["instagram.com"]["evidence"], "clienthello_seen_retransmissions_no_server_response")
        self.assertEqual(result["github.com"]["client_hellos"], 1)
        self.assertEqual(result["github.com"]["tls_alerts"], 1)
        self.assertEqual(result["github.com"]["evidence"], "clienthello_seen_tls_alert_received")


if __name__ == "__main__":
    unittest.main()
