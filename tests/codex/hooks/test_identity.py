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
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("codex/hooks")
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
        self.config_file = self.tmp / "config.toml"
        for name, value in (("CODEX_AUTH_PATH", self.auth_file), ("CODEX_CONFIG_PATH", self.config_file)):
            p = patch.object(unbound, name, value)
            p.start()
            self.addCleanup(p.stop)
        env = patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        for var in ("OPENAI_API_KEY", "CODEX_API_KEY"):
            os.environ.pop(var, None)

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
        self.config_file = self.tmp / "config.toml"
        for name, value in (("CODEX_AUTH_PATH", self.auth_file), ("CODEX_CONFIG_PATH", self.config_file)):
            p = patch.object(unbound, name, value)
            p.start()
            self.addCleanup(p.stop)
        env = patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        for var in ("OPENAI_API_KEY", "CODEX_API_KEY"):
            os.environ.pop(var, None)

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
        """device_serial is the one optional key: a host with no readable serial
        and a cold cache omits it, so pin both shapes rather than the host's."""
        always = {"org_id", "plan", "auth_mode", "email_domain", "user_email"}
        self._write_auth_with_org()
        with patch.object(unbound, "_device_serial", return_value=None):
            self.assertEqual(set(unbound.build_account_identity().keys()), always)
        with patch.object(unbound, "_device_serial", return_value="SERIAL1"):
            self.assertEqual(
                set(unbound.build_account_identity().keys()),
                always | {"device_serial"},
            )


class TestAccountReasonAndGateway(unittest.TestCase):
    """An empty account says why, and a gateway-routed Codex is named by its gateway host."""

    setUp = TestReadAccountIdentity.setUp
    _write_auth = TestReadAccountIdentity._write_auth
    _auth_with_token = TestReadAccountIdentity._auth_with_token

    def _config(self, body):
        self.config_file.write_text(body, encoding="utf-8")

    def test_no_auth_json_says_so(self):
        identity = unbound.read_account_identity()
        self.assertEqual((identity["user_email"], identity["account_reason"]), (None, "auth_json_missing"))

    def test_credentials_kept_in_the_keyring(self):
        for store in ("keyring", "auto", "ephemeral"):
            with self.subTest(store=store):
                self._config('cli_auth_credentials_store = "%s"\n' % store)
                self.assertEqual(unbound.read_account_identity()["account_reason"], "credentials_" + store)

    def test_an_api_key_in_the_environment(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "x"}):
            identity = unbound.read_account_identity()
        self.assertEqual((identity["auth_mode"], identity["account_reason"]), ("api_key", "api_key_env"))

    def test_an_api_key_sign_in(self):
        self._write_auth({"auth_mode": "apikey", "OPENAI_API_KEY": "x"})
        self.assertEqual(unbound.read_account_identity()["account_reason"], "api_key")

    def test_a_subscription_without_an_id_token(self):
        self._write_auth({"auth_mode": "chatgpt", "tokens": {}})
        self.assertEqual(unbound.read_account_identity()["account_reason"], "no_id_token")

    def test_an_id_token_that_cannot_be_decoded(self):
        self._write_auth({"auth_mode": "chatgpt", "tokens": {"id_token": "bad.!!!.token"}})
        self.assertEqual(unbound.read_account_identity()["account_reason"], "id_token_unreadable")

    def test_an_unreadable_auth_json(self):
        self.auth_file.write_text("{not json", encoding="utf-8")
        self.assertEqual(unbound.read_account_identity()["account_reason"], "auth_json_unreadable")

    def test_the_gateway_host_names_an_api_key_account(self):
        self._write_auth({"auth_mode": "apikey", "OPENAI_API_KEY": "x"})
        self._config('openai_base_url = "https://AI-Gateway.zende.sk/v1"\n')
        identity = unbound.read_account_identity()
        self.assertEqual((identity["org_id"], identity["account_reason"]), ("ai-gateway.zende.sk", "api_key"))

    def test_the_chosen_provider_base_url_wins(self):
        self._config('model_provider = "corp"\nopenai_base_url = "https://other.example"\n\n'
                     '[model_providers.corp]\nname = "Corp"\nbase_url = "https://llm.corp.example/v1"\n')
        self.assertEqual(unbound.read_account_identity()["org_id"], "llm.corp.example")

    def test_openai_unbound_and_loopback_hosts_name_no_one(self):
        for url in ("https://api.openai.com/v1", "https://chatgpt.com/backend-api", "https://api.getunbound.ai/v1",
                    "http://localhost:8080", "http://127.0.0.1:4000", "https://openrouter.ai/api/v1",
                    "https://api.groq.com/openai/v1", "https://generativelanguage.googleapis.com/v1beta"):
            with self.subTest(url=url):
                self._config('openai_base_url = "%s"\n' % url)
                self.assertIsNone(unbound.read_account_identity()["org_id"])

    def test_a_company_host_that_merely_ends_like_openai_is_a_gateway(self):
        self._config('openai_base_url = "https://gateway.company-openai.com/v1"\n')
        self.assertEqual(unbound.read_account_identity()["org_id"], "gateway.company-openai.com")

    def test_a_company_azure_openai_host_is_a_gateway(self):
        self._config('openai_base_url = "https://acme.openai.azure.com/openai"\n')
        self.assertEqual(unbound.read_account_identity()["org_id"], "acme.openai.azure.com")

    def test_a_signed_in_account_has_no_reason_and_keeps_its_org(self):
        self._write_auth(self._auth_with_token({
            "email": "dave@corp.com",
            "https://api.openai.com/auth": {"organizations": [{"id": "org-b", "is_default": True}]},
        }))
        self._config('openai_base_url = "https://ai-gateway.zende.sk/v1"\n')
        identity = unbound.read_account_identity()
        self.assertEqual(identity["org_id"], "org-b")
        self.assertNotIn("account_reason", identity)

    def test_the_regex_fallback_accepts_a_commented_provider_header(self):
        raw = ('model_provider = "corp"\nopenai_base_url = "https://root.example"\n\n'
               '[model_providers.corp] # Corporate gateway\nbase_url = "https://llm.corp.example/v1"\n')
        self.assertEqual(unbound._codex_account_config_regex(raw)["model_providers"]["corp"]["base_url"],
                         "https://llm.corp.example/v1")

    def test_the_regex_fallback_ignores_keys_inside_a_leading_table(self):
        raw = '[profiles.x]\ncli_auth_credentials_store = "keyring"\nopenai_base_url = "https://x.example"\n'
        self.assertEqual(unbound._codex_account_config_regex(raw), {})

    def test_a_config_that_fails_to_parse_never_breaks_the_identity(self):
        self._config('openai_base_url = "https://ai-gateway.zende.sk/v1"\n')
        with patch.object(unbound, "_codex_account_config", side_effect=RuntimeError("boom")):
            identity = unbound.read_account_identity()
        self.assertEqual((identity["org_id"], identity["account_reason"]), (None, "auth_json_missing"))

    def test_the_regex_fallback_reads_the_same_keys(self):
        raw = ('model_provider = "corp"\ncli_auth_credentials_store = "keyring"\n\n'
               '[model_providers.corp]\nbase_url = "https://llm.corp.example/v1"\n')
        data = unbound._codex_account_config_regex(raw)
        self.assertEqual(data["cli_auth_credentials_store"], "keyring")
        self.assertEqual(data["model_providers"]["corp"]["base_url"], "https://llm.corp.example/v1")


class TestCodexHome(unittest.TestCase):
    def test_codex_home_moves_auth_and_config(self):
        with patch.dict(os.environ, {"CODEX_HOME": "/tmp/relocated-codex"}):
            spec = importlib.util.spec_from_file_location("codex_home_probe", unbound.__file__)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        self.assertEqual(module.CODEX_AUTH_PATH, Path("/tmp/relocated-codex/auth.json"))
        self.assertEqual(module.CODEX_CONFIG_PATH, Path("/tmp/relocated-codex/config.toml"))


class TestStopExchangeCarriesTheAccount(unittest.TestCase):
    """The turn row is what the account inventory is built from. Codex built the
    identity correctly but never attached it here, so its accounts never appeared
    and nothing failed to say so. Pin the call site."""

    def test_the_stop_payload_asks_for_the_account(self):
        import inspect
        body = inspect.getsource(unbound.process_stop_event)
        self.assertIn("'account_identity': build_account_identity(", body)

    def test_it_probes_rather_than_reading_a_cold_cache(self):
        # The stop path is not latency-critical, and a device serial that was never
        # probed would otherwise stay missing for the whole session.
        import inspect
        body = inspect.getsource(unbound.process_stop_event)
        self.assertIn("build_account_identity(probe=True)", body)


if __name__ == "__main__":
    unittest.main()
