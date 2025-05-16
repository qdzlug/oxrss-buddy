import unittest
import tempfile
import sys
from io import StringIO
from pathlib import Path
from oxide_validator import validate_toml_file, semantic_validation, ip_pool_capacity, main

"""
Test Suite for oxide_rack_validator

This module tests all core functionality of the oxide rack validation tool.

Test Categories
---------------
--TOML Parsing
    - test_valid_toml_parsing
    - test_invalid_toml_syntax
    - test_main_validate_mode

--IP Range Computation
    - test_ip_pool_capacity

--Semantic Validation
    - test_semantic_validation_minimal_valid
    - test_semantic_validation_missing_keys
    - test_main_semantic_mode_with_valid_config
    - test_main_semantic_invalid_ip_range
    - test_main_semantic_missing_required_fields
    - test_main_semantic_invalid_bgp_asn
    - test_main_semantic_invalid_switch_config

--CLI Integration Tests
    - test_main_validate_mode
    - test_main_semantic_mode_with_valid_config
    - test_main_summarize_mode
    - test_main_reformat_mode_to_file
    - test_main_reformat_mode_to_stdout
    - test_main_empty_file
    - test_main_no_args

Each test verifies either functional correctness (e.g. parsing, validation) or CLI exit behavior using `SystemExit` assertions.

Run all tests with:
    python -m unittest tests/test_validator.py
"""


class TestOxideRackValidator(unittest.TestCase):
    def test_valid_toml_parsing(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tf:
            tf.write('[section]\nkey = "value"\n')
            tf.flush()
            self.assertTrue(validate_toml_file(Path(tf.name)))

    def test_invalid_toml_syntax(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tf:
            tf.write('[section\nkey = "value"\n')  # broken header
            tf.flush()
            self.assertFalse(validate_toml_file(Path(tf.name)))

    def test_ip_pool_capacity(self):
        pools = [{"first": "192.168.0.1", "last": "192.168.0.10"}]
        self.assertEqual(ip_pool_capacity(pools), 10)

    def test_semantic_validation_minimal_valid(self):
        config = {
            "external_dns_zone_name": "example.com",
            "external_dns_ips": ["10.0.0.1"],
            "ntp_servers": ["1.1.1.1"],
            "dns_servers": ["8.8.8.8"],
            "internal_services_ip_pool_ranges": [{"first": "10.0.0.2", "last": "10.0.0.20"}],
            "bootstrap_sleds": [1, 2, 3],
            "rack_network_config": {
                "switch0": {
                    "qsfp0": {"addresses": ["192.168.0.1/24"]}
                },
                "switch1": {},
                "bgp": [
                    {"asn": 65000, "originate": ["192.168.0.0/24"]}
                ]
            }
        }
        self.assertTrue(semantic_validation(config))

    def test_semantic_validation_missing_keys(self):
        config = {}  # Completely empty
        self.assertFalse(semantic_validation(config))

    def test_main_validate_mode(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tf:
            tf.write('[section]\nkey = "value"\n')
            tf.flush()
            sys.argv = ["rack-validator", "--validate", tf.name]
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

    def test_main_semantic_mode_with_valid_config(self):
        valid_config = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        valid_config.write('''
external_dns_zone_name = "example.com"
external_dns_ips = ["10.0.0.1"]
ntp_servers = ["1.1.1.1"]
dns_servers = ["8.8.8.8"]
internal_services_ip_pool_ranges = [{first = "10.0.0.2", last = "10.0.0.20"}]
bootstrap_sleds = [1, 2, 3]
[rack_network_config.switch0.qsfp0]
addresses = ["192.168.0.1/24"]
[rack_network_config.switch1]
[[rack_network_config.bgp]]
asn = 65000
originate = ["192.168.0.0/24"]
''')
        valid_config.flush()
        sys.argv = ["rack-validator", "--semantic", valid_config.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)

    def test_main_summarize_mode(self):
        minimal = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        minimal.write('''
external_dns_zone_name = "example.com"
external_dns_ips = ["10.0.0.1"]
ntp_servers = ["1.1.1.1"]
dns_servers = ["8.8.8.8"]
internal_services_ip_pool_ranges = [{first = "10.0.0.2", last = "10.0.0.20"}]
bootstrap_sleds = [1, 2, 3]
[rack_network_config.switch0.qsfp0]
addresses = ["192.168.0.1/24"]
[rack_network_config.switch1]
[[rack_network_config.bgp]]
asn = 65000
originate = ["192.168.0.0/24"]
''')
        minimal.flush()
        sys.argv = ["rack-validator", "--summarize", minimal.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)

    def test_main_reformat_mode_to_file(self):
        source = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        source.write('external_dns_zone_name = "example.com" ')
        source.flush()

        out_path = Path(source.name + ".out")
        sys.argv = ["rack-validator", "--reformat", source.name, "--output", str(out_path)]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)
        self.assertTrue(out_path.exists())
        content = out_path.read_text()
        self.assertIn("external_dns_zone_name", content)

    def test_main_reformat_mode_to_stdout(self):
        source = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        source.write('external_dns_zone_name = "example.com" ')
        source.flush()

        sys.argv = ["rack-validator", "--reformat", source.name, "--output", "-"]

        from io import BytesIO
        import builtins
        saved_stdout = sys.stdout

        class FakeStdout:
            def __init__(self):
                self.buffer = BytesIO()
            def write(self, msg):
                saved_stdout.write(msg)
            def flush(self):
                saved_stdout.flush()

        sys.stdout = FakeStdout()

        try:
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)
            output = sys.stdout.buffer.getvalue().decode()
            self.assertIn("external_dns_zone_name", output)
        finally:
            sys.stdout = saved_stdout
            sys.stdout = saved_stdout

    def test_main_semantic_invalid_ip_range(self):
        broken = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        broken.write('''
external_dns_zone_name = "example.com"
external_dns_ips = ["10.0.0.1"]
ntp_servers = ["1.1.1.1"]
dns_servers = ["8.8.8.8"]
internal_services_ip_pool_ranges = [{first = "bad_ip", last = "10.0.0.20"}]
bootstrap_sleds = [1, 2, 3]
''')
        broken.flush()
        sys.argv = ["rack-validator", "--semantic", broken.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    def test_main_semantic_missing_required_fields(self):
        broken = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)

        broken.write('''[rack_network_config.switch0.qsfp0]
        addresses = ["192.168.0.1/24"]
        ''')
        broken.flush()
        sys.argv = ["rack-validator", "--semantic", broken.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    def test_main_semantic_invalid_bgp_asn(self):
        broken = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        broken.write('''
external_dns_zone_name = "example.com"
external_dns_ips = ["10.0.0.1"]
ntp_servers = ["1.1.1.1"]
dns_servers = ["8.8.8.8"]
internal_services_ip_pool_ranges = [{first = "10.0.0.2", last = "10.0.0.20"}]
bootstrap_sleds = [1, 2, 3]
[rack_network_config.switch0.qsfp0]
addresses = ["192.168.0.1/24"]
[rack_network_config.switch1]
[[rack_network_config.bgp]]
asn = 0
originate = ["192.168.0.0/24"]
''')
        broken.flush()
        sys.argv = ["rack-validator", "--semantic", broken.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    def test_main_semantic_invalid_switch_config(self):
        broken = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        broken.write('''
external_dns_zone_name = "example.com"
external_dns_ips = ["10.0.0.1"]
ntp_servers = ["1.1.1.1"]
dns_servers = ["8.8.8.8"]
internal_services_ip_pool_ranges = [{first = "10.0.0.2", last = "10.0.0.20"}]
bootstrap_sleds = [1, 2, 3]
[rack_network_config.switch0.qsfp0]
addresses = ["not_a_cidr"]
[rack_network_config.switch1]
[[rack_network_config.bgp]]
asn = 65000
originate = ["192.168.0.0/24"]
''')
        broken.flush()
        sys.argv = ["rack-validator", "--semantic", broken.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    def test_main_invalid_toml_table(self):
        broken = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        broken.write('[unclosed\nkey = "value"\n')  # invalid table
        broken.flush()
        sys.argv = ["rack-validator", "--validate", broken.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertNotEqual(cm.exception.code, 0)

    def test_main_empty_file(self):
        empty = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
        empty.write("# empty file\n")
        empty.flush()
        sys.argv = ["rack-validator", "--semantic", empty.name]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    def test_main_no_args(self):
        sys.argv = ["rack-validator"]
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertGreaterEqual(cm.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
