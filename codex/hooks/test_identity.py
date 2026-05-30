"""
Tests for account-identity helpers in codex/hooks/unbound.py.

Covers:
  - _email_domain
  - _decode_jwt_claims
  - _codex_org_id
  - read_account_identity
  - build_account_identity
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    """Build a minimal 3-part JWT whose middle segment encodes `payload`."""
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b'=').decode()
    payload_bytes = json.dumps(payload).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()
    return f"{header_b64}.{payload_b64}.fakesig"


def _make_jwt_padded(payload: dict) -> str:
    """Build a JWT whose payload segment has standard base64 padding (=)."""
    header_b64 = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode()
    payload_bytes = json.dumps(payload).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()
    return f"{header_b64}.{payload_b64}.fakesig"


# ---------------------------------------------------------------------------
# _email_domain
# ---------------------------------------------------------------------------

class TestEmailDomain(unittest.TestCase):
    def test_happy_path(self):
        self.assertEqual(unbound._email_domain("alice@acme.com"), "acme.com")

    def test_lowercase_normalisation(self):
        self.assertEqual(unbound._email_domain("Alice@ACME.COM"), "acme.com")

    def test_none_returns_none(self):
        self.assertIsNone(unbound._email_domain(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(unbound._email_domain(""))

    def test_no_at_sign_returns_none(self):
        self.assertIsNone(unbound._email_domain("notemail"))

    def test_empty_domain_returns_none(self):
        self.assertIsNone(unbound._email_domain("user@"))


# ---------------------------------------------------------------------------
# _decode_jwt_claims
# ---------------------------------------------------------------------------

class TestDecodeJwtClaims(unittest.TestCase):
    def test_decodes_standard_claims(self):
        payload = {"sub": "u-123", "email": "bob@example.com"}
        token = _make_jwt(payload)
        claims = unbound._decode_jwt_claims(token)
        self.assertEqual(claims["sub"], "u-123")
        self.assertEqual(claims["email"], "bob@example.com")

    def test_decodes_without_padding(self):
        # segment length not divisible by 4 → padding must be added by the impl
        payload = {"x": "y" * 3}   # ensure unpadded segment
        token = _make_jwt(payload)
        # strip any residual '=' to guarantee no padding
        parts = token.split('.')
        parts[1] = parts[1].rstrip('=')
        token_no_pad = '.'.join(parts)
        claims = unbound._decode_jwt_claims(token_no_pad)
        self.assertEqual(claims["x"], "y" * 3)

    def test_decodes_with_existing_padding(self):
        payload = {"hello": "world"}
        token = _make_jwt_padded(payload)
        claims = unbound._decode_jwt_claims(token)
        self.assertEqual(claims["hello"], "world")

    def test_nested_auth_claim_extracted(self):
        payload = {
            "email": "charlie@corp.com",
            "https://api.openai.com/auth": {
                "organizations": [
                    {"id": "org-default", "is_default": True},
                ],
                "chatgpt_plan_type": "pro",
            }
        }
        token = _make_jwt(payload)
        claims = unbound._decode_jwt_claims(token)
        auth_claim = claims["https://api.openai.com/auth"]
        self.assertEqual(auth_claim["chatgpt_plan_type"], "pro")
        self.assertEqual(auth_claim["organizations"][0]["id"], "org-default")

    def test_malformed_token_returns_empty_dict(self):
        result = unbound._decode_jwt_claims("not.a.jwt")
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_single_segment_token_returns_empty_dict(self):
        result = unbound._decode_jwt_claims("onlyone")
        self.assertEqual(result, {})

    def test_garbage_base64_returns_empty_dict(self):
        result = unbound._decode_jwt_claims("aaa.!!!.bbb")
        self.assertEqual(result, {})

    def test_empty_string_returns_empty_dict(self):
        result = unbound._decode_jwt_claims("")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# _codex_org_id
# ---------------------------------------------------------------------------

class TestCodexOrgId(unittest.TestCase):
    def test_picks_is_default_org(self):
        claim = {
            "organizations": [
                {"id": "org-other", "is_default": False},
                {"id": "org-main", "is_default": True},
            ]
        }
        self.assertEqual(unbound._codex_org_id(claim), "org-main")

    def test_falls_back_to_first_when_no_default(self):
        claim = {
            "organizations": [
                {"id": "org-first"},
                {"id": "org-second"},
            ]
        }
        self.assertEqual(unbound._codex_org_id(claim), "org-first")

    def test_returns_none_for_empty_list(self):
        self.assertIsNone(unbound._codex_org_id({"organizations": []}))

    def test_returns_none_when_no_organizations_key(self):
        self.assertIsNone(unbound._codex_org_id({}))

    def test_returns_none_when_organizations_not_list(self):
        self.assertIsNone(unbound._codex_org_id({"organizations": "not-a-list"}))

    def test_returns_none_when_id_missing(self):
        claim = {"organizations": [{"is_default": True}]}
        self.assertIsNone(unbound._codex_org_id(claim))


# ---------------------------------------------------------------------------
# read_account_identity
# ---------------------------------------------------------------------------

class TestReadAccountIdentity(unittest.TestCase):
    """Test read_account_identity() via a mocked CODEX_AUTH_PATH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.auth_file = self.tmp / "auth.json"
        self._p = patch.object(unbound, "CODEX_AUTH_PATH", self.auth_file)
        self._p.start()
        self.addCleanup(self._p.stop)

    def _write_auth(self, data):
        self.auth_file.write_text(json.dumps(data), encoding="utf-8")

    def _auth_with_token(self, payload, auth_mode="chatgpt"):
        token = _make_jwt(payload)
        return {
            "auth_mode": auth_mode,
            "tokens": {"id_token": token},
        }

    def test_org_id_from_is_default_org(self):
        self._write_auth(self._auth_with_token({
            "email": "dave@corp.com",
            "https://api.openai.com/auth": {
                "organizations": [
                    {"id": "org-a", "is_default": False},
                    {"id": "org-b", "is_default": True},
                ],
                "chatgpt_plan_type": "team",
            }
        }))
        result = unbound.read_account_identity()
        self.assertEqual(result["org_id"], "org-b")

    def test_plan_from_chatgpt_plan_type(self):
        self._write_auth(self._auth_with_token({
            "email": "eve@corp.com",
            "https://api.openai.com/auth": {
                "organizations": [{"id": "org-x", "is_default": True}],
                "chatgpt_plan_type": "enterprise",
            }
        }))
        result = unbound.read_account_identity()
        self.assertEqual(result["plan"], "enterprise")

    def test_email_domain_from_top_level_email_claim(self):
        self._write_auth(self._auth_with_token({
            "email": "frank@example.org",
            "https://api.openai.com/auth": {
                "organizations": [{"id": "org-y", "is_default": True}],
            }
        }))
        result = unbound.read_account_identity()
        self.assertEqual(result["email_domain"], "example.org")

    def test_chatgpt_auth_mode_maps_to_subscription(self):
        self._write_auth(self._auth_with_token({"email": "x@x.com"}, auth_mode="chatgpt"))
        result = unbound.read_account_identity()
        self.assertEqual(result["auth_mode"], "subscription")

    def test_apikey_auth_mode_maps_to_api_key(self):
        self._write_auth(self._auth_with_token({"email": "x@x.com"}, auth_mode="apikey"))
        result = unbound.read_account_identity()
        self.assertEqual(result["auth_mode"], "api_key")

    def test_unknown_auth_mode_gives_none(self):
        self._write_auth(self._auth_with_token({"email": "x@x.com"}, auth_mode="sso"))
        result = unbound.read_account_identity()
        self.assertIsNone(result["auth_mode"])

    def test_missing_file_returns_all_nulls(self):
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        self.assertIsNone(result["auth_mode"])
        self.assertIsNone(result["email_domain"])

    def test_missing_file_does_not_raise(self):
        try:
            unbound.read_account_identity()
        except Exception as exc:
            self.fail(f"raised {exc!r}")

    def test_malformed_json_returns_all_nulls(self):
        self.auth_file.write_text("{broken", encoding="utf-8")
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["auth_mode"])

    def test_malformed_json_does_not_raise(self):
        self.auth_file.write_text("{broken", encoding="utf-8")
        try:
            unbound.read_account_identity()
        except Exception as exc:
            self.fail(f"raised {exc!r}")

    def test_bad_token_in_id_token_returns_nulls(self):
        self._write_auth({
            "auth_mode": "chatgpt",
            "tokens": {"id_token": "bad.!!!.token"},
        })
        result = unbound.read_account_identity()
        self.assertIsNone(result["org_id"])
        self.assertIsNone(result["plan"])
        # auth_mode is still read from the top-level auth_mode field
        self.assertEqual(result["auth_mode"], "subscription")


# ---------------------------------------------------------------------------
# build_account_identity
# ---------------------------------------------------------------------------

class TestBuildAccountIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.auth_file = self.tmp / "auth.json"
        self._p = patch.object(unbound, "CODEX_AUTH_PATH", self.auth_file)
        self._p.start()
        self.addCleanup(self._p.stop)

    def _write_auth_with_org(self, org_id="org-test", email="test@example.com"):
        token = _make_jwt({
            "email": email,
            "https://api.openai.com/auth": {
                "organizations": [{"id": org_id, "is_default": True}],
                "chatgpt_plan_type": "pro",
            }
        })
        self.auth_file.write_text(json.dumps({
            "auth_mode": "chatgpt",
            "tokens": {"id_token": token},
        }), encoding="utf-8")

    def test_returns_full_identity(self):
        self._write_auth_with_org("org-test", "user@domain.com")
        result = unbound.build_account_identity()
        self.assertEqual(result["org_id"], "org-test")
        self.assertEqual(result["email_domain"], "domain.com")
        self.assertEqual(result["auth_mode"], "subscription")
        self.assertEqual(result["plan"], "pro")

    def test_keys_limited_to_identity_fields(self):
        result = unbound.build_account_identity()
        self.assertEqual(
            set(result.keys()), {"org_id", "plan", "auth_mode", "email_domain"}
        )


if __name__ == "__main__":
    unittest.main()
