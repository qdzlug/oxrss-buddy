import unittest
from unittest.mock import patch
from io import BytesIO, StringIO
from types import SimpleNamespace
from contextlib import redirect_stdout
import os
import json

from oxide_validator.generate_config import generate_config

FIXTURE_DIR = "tests/fixtures/test_input_sessions"

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

def load_sessions():
    for fname in os.listdir(FIXTURE_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(FIXTURE_DIR, fname)) as f:
                data = json.load(f)
            yield fname, data["text_inputs"], data["confirm_inputs"]

class TestGeneratedSessions(unittest.TestCase):
    def test_session_files(self):
        for fname, text_inputs, confirm_inputs in load_sessions():
            with self.subTest(session=fname):
                result = run_generator_with_prompts(text_inputs, confirm_inputs)
                self.assertIsInstance(result, dict, f"{fname} did not return a dict")
                self.assertIn("rack_network_config", result, f"{fname} missing 'rack_network_config'")
