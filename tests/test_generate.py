import unittest
from unittest.mock import patch
from io import BytesIO, StringIO
import tomli
import json
from types import SimpleNamespace
from contextlib import redirect_stdout

from oxide_validator.generate_config import generate_config

def run_generator_with_prompts(text_answers, confirm_answers):
    toml_output = BytesIO()
    stdout_capture = StringIO()
    mock_stdout = SimpleNamespace(buffer=toml_output, write=stdout_capture.write)

    with patch("questionary.text") as mock_text, patch("questionary.confirm") as mock_confirm:
        mock_text().ask.side_effect = text_answers
        mock_confirm().ask.side_effect = confirm_answers
        with patch("sys.stdout", mock_stdout), redirect_stdout(stdout_capture):
            result = generate_config()
        return result

class TestGenerateConfig(unittest.TestCase):

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_generate_minimal_config(self, mock_confirm, mock_text):
        mock_text().ask.side_effect = [
            "oxide.example.com", "10.0.0.10", "1.1.1.1",
            "10.10.0.0/24", "10.10.0.105",
            "10.10.0.1", "10.10.0.254",
            "1-3", "-"
        ]
        mock_confirm().ask.side_effect = [False, True, False, False]

        result = generate_config()
        self.assertEqual(result["allowed_source_ips"]["allow"], "any")
        self.assertEqual(result["rack_network_config"]["infra_ip_first"], "10.10.0.1")
        self.assertEqual(result["rack_network_config"]["infra_ip_last"], "10.10.0.254")
        self.assertEqual(result["bootstrap_sleds"], [1, 2, 3])

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_source_ip_allowlist(self, mock_confirm, mock_text):
        mock_text().ask.side_effect = [
            "zone.list", "8.8.8.8", "1.1.1.1",
            "10.10.0.0/28", "10.10.0.1",
            "10.1.1.0/24,10.2.2.0/24",
            "10.0.0.2", "10.0.0.10",
            "1-3", "-"
        ]
        mock_confirm().ask.side_effect = [False, False, False, False]

        result = generate_config()
        self.assertEqual(result["allowed_source_ips"]["allow"], "list")
        self.assertIn("10.1.1.0/24", result["allowed_source_ips"]["ips"])
        self.assertIn("10.2.2.0/24", result["allowed_source_ips"]["ips"])
        self.assertEqual(result["bootstrap_sleds"], [1, 2, 3])

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_generate_with_bgp(self, mock_confirm, mock_text):
        mock_text().ask.side_effect = [
            "oxide.bgp", "10.0.0.1", "2.2.2.2",
            "10.0.0.0/28", "10.0.0.3",
            "10.0.0.10", "10.0.0.20",
            "8,9", "65001", "10.1.0.0/24", "-"
        ]
        mock_confirm().ask.side_effect = [False, True, True, False, False]

        result = generate_config()
        bgp_config = result["rack_network_config"]["bgp"]
        self.assertEqual(bgp_config[0]["asn"], 65001)
        self.assertIn("10.1.0.0/24", bgp_config[0]["originate"])

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_sled_range_recovers(self, mock_confirm, mock_text):
        print("\n--- test_sled_range_recovers ---")
        mock_text().ask.side_effect = [
            "oxide.invalid",  # zone
            "10.0.0.20",  # external DNS
            "3.3.3.3",  # NTP
            "10.0.0.200-10.0.0.210",  # internal IP range
            "10.0.0.205",  # internal DNS
            "10.0.0.2",  # infra_ip_first
            "10.0.0.10",  # infra_ip_last
            "1-33",  # ❌ invalid sled input (should retry)
            "1-2",  # ✅ valid sled input
            "-"  # output
        ]
        mock_confirm().ask.side_effect = [
            False,  # no extra internal IP range
            True,  # allow any source IP
            False,  # no BGP
            False  # no switch port
        ]

        result = generate_config()
        assert result["bootstrap_sleds"] == [1, 2], "Expected sleds to be parsed after retry"

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_generate_with_multiple_bgp_prefixes(self, mock_confirm, mock_text):
        mock_text().ask.side_effect = [
            "zone.bgp", "10.10.10.10", "4.4.4.4",
            "10.10.10.0/28", "10.10.10.5",
            "10.0.0.2", "10.0.0.10",
            "4-6", "65010", "10.1.0.0/24,10.2.0.0/24", "-"
        ]
        mock_confirm().ask.side_effect = [False, True, True, False, False]

        result = generate_config()
        bgp = result["rack_network_config"]["bgp"]
        self.assertEqual(bgp[0]["asn"], 65010)
        self.assertIn("10.1.0.0/24", bgp[0]["originate"])
        self.assertIn("10.2.0.0/24", bgp[0]["originate"])

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_generate_bgp_with_invalid_asn(self, mock_confirm, mock_text):
        print("\n--- test_generate_bgp_with_invalid_asn ---")
        mock_text().ask.side_effect = [
            "zone.invalid",  # DNS zone
            "8.8.8.8",  # External DNS
            "1.2.3.4",  # NTP
            "192.168.1.0/28",  # IP range
            "192.168.1.5",  # Internal DNS
            "10.0.0.10",  # infra first
            "10.0.0.30",  # infra last
            "1-2",  # sleds
            "0",  # ❌ invalid ASN
            "65001",  # ✅ valid ASN on retry
            "10.5.0.0/24",  # BGP prefix
            "-"  # output
        ]
        mock_confirm().ask.side_effect = [
            False,  # no extra range
            True,  # allow any
            True,  # add bgp
            True,  # add bgp
            False,  # no switch port
            False,  # no switch port
        ]

        result = generate_config()
        bgp = result["rack_network_config"]["bgp"]
        self.assertEqual(bgp[0]["asn"], 65001)
        self.assertIn("10.5.0.0/24", bgp[0]["originate"])

    @patch("questionary.text")
    @patch("questionary.confirm")
    def test_generate_bgp_with_invalid_prefix(self, mock_confirm, mock_text):
        mock_text().ask.side_effect = [
            "zone.badprefix", "9.9.9.9", "5.5.5.5",
            "172.16.0.0/28", "172.16.0.5",
            "10.0.0.1", "10.0.0.3",
            "10,11", "64512", "not_a_prefix", "-"
        ]
        mock_confirm().ask.side_effect = [False, True, True, False, False]

        result = generate_config()
        self.assertEqual(result["rack_network_config"]["bgp"], [])

if __name__ == '__main__':
    unittest.main()