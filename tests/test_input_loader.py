import unittest
import json
import os
from unittest.mock import patch
from io import BytesIO, StringIO
from types import SimpleNamespace
from contextlib import redirect_stdout

from oxide_validator.generate_config import generate_config

FIXTURE_DIR = "tests/fixtures/test_input_sessions"

def run_generator_with_prompts(text_inputs, confirm_inputs):
    toml_output = BytesIO()
    stdout_capture = StringIO()
    mock_stdout = SimpleNamespace(buffer=toml_output, write=stdout_capture.write)

    with patch("questionary.text") as mock_text, patch("questionary.confirm") as mock_confirm:
        mock_text().ask.side_effect = text_inputs
        mock_confirm().ask.side_effect = confirm_inputs
        with patch("sys.stdout", mock_stdout), redirect_stdout(stdout_capture):
            result = generate_config()
        output = stdout_capture.getvalue()
        return result, output

class TestGeneratedSessions(unittest.TestCase):
    def test_session_files(self):
        for fname in sorted(os.listdir(FIXTURE_DIR)):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(FIXTURE_DIR, fname)
            with self.subTest(session=fname):
                with open(path) as f:
                    data = json.load(f)

                text_inputs = data.get("text_inputs")
                confirm_inputs = data.get("confirm_inputs")

                self.assertIsInstance(text_inputs, list, f"{fname} missing or invalid 'text_inputs'")
                self.assertIsInstance(confirm_inputs, list, f"{fname} missing or invalid 'confirm_inputs'")

                result, output = run_generator_with_prompts(text_inputs, confirm_inputs)
                self.assertIsInstance(result, dict, f"{fname} did not return a valid config dictionary")
                self.assertIn("rack_network_config", result, f"{fname} missing 'rack_network_config' section")

                print("\n" + "=" * 80)
                print(f"🔍 Output for {fname}")
                print("=" * 80)
                print(json.dumps(result, indent=2))
                print("=" * 80 + "\n")

if __name__ == '__main__':
    unittest.main(buffer=False, verbosity=2)