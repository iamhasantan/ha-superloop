"""Tests for token helpers. Run with python -m unittest discover -s tests."""

import base64
import importlib.util
import json
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "superloop" / "token_utils.py"
spec = importlib.util.spec_from_file_location("superloop_token_utils", MODULE_PATH)
utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils)


def jwt(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "header." + encoded + ".signature"


class TokenUtilsTests(unittest.TestCase):
    def test_expiry_from_valid_jwt(self):
        self.assertEqual(utils.jwt_expiry_ms(jwt({"exp": 1793701860})), 1793701860000)

    def test_reject_boolean_and_string_expiry(self):
        self.assertIsNone(utils.jwt_expiry_ms(jwt({"exp": True})))
        self.assertIsNone(utils.jwt_expiry_ms(jwt({"exp": "1793701860"})))

    def test_opaque_token_and_invalid_jwt(self):
        self.assertIsNone(utils.jwt_expiry_ms("opaque-token"))
        self.assertIsNone(utils.jwt_expiry_ms("a.b.c"))
        self.assertIsNone(utils.jwt_expiry_ms(jwt({"some_other_claim": 1})))

    def test_bearer_prefix(self):
        self.assertEqual(utils.strip_bearer_prefix("  Bearer abc.def.xyz  "), "abc.def.xyz")
        self.assertEqual(utils.strip_bearer_prefix("bearer abc"), "abc")
        self.assertEqual(utils.strip_bearer_prefix(" abc "), "abc")


if __name__ == "__main__":
    unittest.main()
