import unittest
from unittest.mock import patch
from io import BytesIO
import tomli

from oxide_validator.generate_config import generate_config

class TestGenerateConfig(unittest.TestCase):
    @patch("questionary.confirm")
    @patch("questionary.text")
    def test_generate_minimal_config(self, mock_text, mock_confirm):
        # Simulated prompt inputs in order of expected prompts
        mock_text().ask.side_effect = [
            "oxide.example.com",         # external_dns_zone_name
            "10.0.0.10",                 # external_dns_ips
            "1.1.1.1",                   # ntp_servers
            "10.0.0.100-10.0.0.110",     # internal IP range
            "10.0.0.105",                # internal DNS
            "1-3",                       # sleds
            "-"                           # output to stdout
        ]
        mock_confirm().ask.side_effect = [False, False]  # 1 IP range, no BGP

        from types import SimpleNamespace
        mock_stdout = SimpleNamespace(buffer=BytesIO())

        with patch("sys.stdout", mock_stdout):
            generate_config()
            result = tomli.loads(mock_stdout.buffer.getvalue().decode())

        self.assertEqual(result["external_dns_zone_name"], "oxide.example.com")
        self.assertIn("10.0.0.105", result["dns_servers"])
        self.assertEqual(result["bootstrap_sleds"], [1, 2, 3])
        self.assertEqual(result["rack_network_config"], {"bgp": []})

if __name__ == '__main__':
    unittest.main()
