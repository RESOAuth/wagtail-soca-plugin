import io
import json
from datetime import timedelta
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from wagtail_soca.config import get_config
from wagtail_soca.models import LoginTransaction

from .provider import ISSUER, Provider


class LoginTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="editor", email="editor@example.com", password="local-password"
        )
        cls.user.user_permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )

    def setUp(self):
        self.provider = Provider()
        self.transport = patch("wagtail_soca.http.request_json", side_effect=self.provider.fetch)
        self.mock_http = self.transport.start()
        self.addCleanup(self.transport.stop)

    def start(self, client=None, destination="/admin/"):
        client = client or self.client
        response = client.get("/soca/login/", {"next": destination}, secure=True)
        self.assertEqual(response.status_code, 302)
        self.assertIn("no-store", response["Cache-Control"])
        return self.provider.authorize(response["Location"])

    def finish(self, params=None, client=None):
        params = self.start(client=client) if params is None else params
        return (client or self.client).get("/soca/callback/", params, secure=True)

    def test_full_login_and_wagtail_admin(self):
        response = self.finish(self.start(destination="/admin/pages/"))
        self.assertRedirects(response, "/admin/pages/", fetch_redirect_response=False)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
        self.assertEqual(self.client.get("/admin/", secure=True).status_code, 200)
        self.assertTrue(LoginTransaction.objects.get().consumed)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_superuser)
        self.assertFalse(self.user.is_staff)

    def test_metadata_and_keys_are_public_and_stable(self):
        config = get_config()
        self.assertEqual(self.client.get("/soca/client.json").json(), config.document())
        keys = self.client.get("/soca/jwks.json").json()
        self.assertNotIn("d", keys["keys"][0])
        self.assertEqual(keys, self.client.get("/soca/jwks.json").json())
        self.assertNotIn("PRIVATE", str(keys))
        self.assertEqual(self.client.post("/soca/client.json").status_code, 405)

    def test_login_button_and_local_password_recovery(self):
        response = self.client.get("/admin/login/", secure=True)
        self.assertContains(response, "Continue with SSO")
        self.assertContains(response, 'name="password"')
        response = self.client.post(
            "/admin/login/",
            {"username": "editor", "password": "local-password", "next": "/admin/"},
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    @override_settings(SOCA={"ENABLED": False})
    def test_disabled_does_not_break_local_login(self):
        self.assertNotContains(self.client.get("/admin/login/", secure=True), "Continue with SSO")
        self.assertEqual(self.client.get("/soca/client.json").status_code, 404)
        self.assertEqual(self.client.get("/soca/login/", secure=True).status_code, 403)

    def test_replayed_callback_is_rejected_without_redeeming_again(self):
        params = self.start()
        self.assertEqual(self.finish(params).status_code, 302)
        self.assertEqual(self.finish(params).status_code, 403)
        self.assertEqual(
            sum(call.args[0] == ISSUER + "/token" for call in self.mock_http.call_args_list), 1
        )

    def test_browser_binding_and_state_rejection(self):
        params = self.start()
        self.assertEqual(self.finish(params, client=Client()).status_code, 403)
        self.assertFalse(LoginTransaction.objects.get().consumed)
        bad = dict(params, state="x" * 43)
        self.assertEqual(self.finish(bad).status_code, 403)
        self.assertEqual(self.finish(params).status_code, 302)

    def test_expired_transaction(self):
        params = self.start()
        LoginTransaction.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.finish(params).status_code, 403)
        self.assertIsNone(self.provider.last_form)

    def test_transaction_payload_is_encrypted(self):
        params = self.start()
        row = LoginTransaction.objects.get()
        self.assertNotIn(params["state"], row.state_digest)
        self.assertNotIn("nonce", row.payload)
        self.assertNotIn("verifier", row.payload)
        self.assertNotIn("provider.example.com", row.payload)

    def test_configuration_change_invalidates_transaction(self):
        params = self.start()
        with override_settings(SOCA={**settings.SOCA, "ALLOW_DOMAINS": ["other.example"]}):
            self.assertEqual(self.finish(params).status_code, 403)
        self.assertIsNone(self.provider.last_form)

    def test_signing_key_change_invalidates_transaction(self):
        params = self.start()
        new_key = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        with override_settings(SOCA={**settings.SOCA, "PRIVATE_KEY": new_key}):
            self.assertEqual(self.finish(params).status_code, 403)
        self.assertIsNone(self.provider.last_form)

    def test_rs256_provider(self):
        self.provider.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.provider.public = json.loads(
            jwt.algorithms.RSAAlgorithm.to_jwk(self.provider.key.public_key())
        )
        self.provider.public.update(kid="provider-key", use="sig", alg="RS256")
        self.provider.jwks = {"keys": [self.provider.public]}
        with override_settings(SOCA={**settings.SOCA, "ID_TOKEN_ALG": "RS256"}):
            self.assertEqual(self.finish().status_code, 302)

    def test_missing_or_wrong_response_issuer(self):
        for issuer in (None, "https://attacker.example.com"):
            with self.subTest(issuer=issuer):
                params = self.start()
                if issuer is None:
                    params.pop("iss")
                else:
                    params["iss"] = issuer
                self.assertEqual(self.finish(params).status_code, 403)
        self.assertIsNone(self.provider.last_form)

    def test_duplicate_parameters_and_provider_error_are_redacted(self):
        params = self.start()
        response = self.finish({**params, "state": [params["state"], params["state"]]})
        self.assertEqual(response.status_code, 403)
        response = self.finish({**params, "error": "secret-provider-diagnostic"})
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(response, "secret-provider-diagnostic", status_code=403)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")

    def test_external_redirects_are_discarded(self):
        for target in (
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            "javascript:alert(1)",
        ):
            with self.subTest(target=target):
                self.client.logout()
                response = self.finish(self.start(destination=target))
                self.assertEqual(response["Location"], "/admin/")

    def test_invalid_claims_fail_closed(self):
        cases = [
            {"nonce": "wrong"},
            {"iss": "https://evil.example"},
            {"aud": "other-client"},
            {"aud": [get_config().client_id, "other"]},
            {"azp": "other"},
            {"sub": ""},
            {"sub": 123},
            {"iat": "123"},
            {"iat": True},
            {"exp": 1},
            {"exp": 9999999999},
            {"nbf": 9999999999},
            {"email_verified": False},
            {"email_verified": "true"},
            {"email": "bad-email"},
            {"at_hash": "wrong"},
            {"c_hash": "wrong"},
            {"nonce": "é"},
        ]
        for claims in cases:
            with self.subTest(claims=claims):
                self.provider.overrides = claims
                self.assertEqual(self.finish().status_code, 403)
                self.assertNotIn("_auth_user_id", self.client.session)

    def test_subject_matched_userinfo_fallback(self):
        self.provider.omit = {"email", "email_verified"}
        self.assertEqual(self.finish().status_code, 302)

    def test_userinfo_mismatch_and_conflicts(self):
        self.provider.omit = {"email_verified"}
        for info in (
            {"sub": "other-person"},
            {"email": "other@example.com"},
            {"email_verified": "true"},
        ):
            with self.subTest(info=info):
                original = self.provider.userinfo.copy()
                self.provider.userinfo.update(info)
                self.assertEqual(self.finish().status_code, 403)
                self.provider.userinfo = original

    def test_jose_header_and_ambiguous_key_rejected(self):
        for headers in (
            {"kid": "missing"},
            {"kid": "provider-key", "jku": "https://evil.example/keys"},
            {"kid": "provider-key", "crit": []},
            {"kid": "provider-key", "typ": "at+jwt"},
        ):
            with self.subTest(headers=headers):
                self.provider.headers = headers
                self.assertEqual(self.finish().status_code, 403)
        self.provider.headers = {"kid": "provider-key"}
        self.provider.jwks = {"keys": [self.provider.public, self.provider.public]}
        self.assertEqual(self.finish().status_code, 403)

    def test_bad_signature_and_symmetric_algorithm_rejected(self):
        other_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.provider.jwks["keys"] = [
            {**self.provider.public, **json.loads(jwt.algorithms.ECAlgorithm.to_jwk(other_key))}
        ]
        self.assertEqual(self.finish().status_code, 403)
        self.provider.jwks = {"keys": [self.provider.public]}
        original_encode = jwt.encode

        def hmac_token(claims, key, **kwargs):
            return original_encode(
                claims,
                "untrusted-provider-secret" * 2,
                algorithm="HS256",
                headers={"kid": "provider-key"},
            )

        # The client assertion still uses the real ES256 encoder; only replace the provider token.
        with patch(
            "tests.provider.jwt.encode",
            side_effect=lambda claims, key, **kw: (
                hmac_token(claims, key)
                if claims.get("iss") == ISSUER
                else original_encode(claims, key, **kw)
            ),
        ):
            self.assertEqual(self.finish().status_code, 403)

    def test_deny_overrides_allow_and_empty_allow_denies_all(self):
        for policy in (
            {"DENY_EMAILS": ["editor@example.com"]},
            {"DENY_DOMAINS": ["example.com"]},
            {"ALLOW_DOMAINS": []},
        ):
            with self.subTest(policy=policy), override_settings(SOCA={**settings.SOCA, **policy}):
                self.assertEqual(self.finish().status_code, 403)

    def test_allow_email_case_insensitive_and_no_subdomain_wildcard(self):
        with override_settings(
            SOCA={**settings.SOCA, "ALLOW_DOMAINS": [], "ALLOW_EMAILS": ["EDITOR@example.com"]}
        ):
            self.provider.overrides = {"email": "Editor@Example.com"}
            self.assertEqual(self.finish().status_code, 302)
        self.client.logout()
        self.provider.overrides = {"email": "editor@sub.example.com"}
        self.assertEqual(self.finish().status_code, 403)

    def test_missing_duplicate_inactive_and_non_editor_accounts(self):
        self.provider.overrides = {"email": "missing@example.com"}
        self.assertEqual(self.finish().status_code, 403)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.provider.overrides = {}
        duplicate = get_user_model().objects.create_user(
            username="duplicate", email="EDITOR@example.com"
        )
        self.assertEqual(self.finish().status_code, 403)
        duplicate.delete()
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.finish().status_code, 403)
        self.user.is_active = True
        self.user.save()
        self.user.user_permissions.clear()
        self.assertEqual(self.finish().status_code, 403)

    def test_discovery_failures(self):
        for change in (
            {"issuer": "https://evil.example"},
            {"code_challenge_methods_supported": []},
            {"client_id_metadata_document_supported": False},
            {"subject_types_supported": [{}]},
            {"authorization_endpoint": ISSUER + "/authorize?state=bad"},
            {"token_endpoint": "http://provider.example.com/token"},
        ):
            with self.subTest(change=change):
                original = self.provider.document.copy()
                self.provider.document.update(change)
                self.assertEqual(self.client.get("/soca/login/", secure=True).status_code, 403)
                self.provider.document = original

    def test_assertion_token_endpoint_audience(self):
        with override_settings(SOCA={**settings.SOCA, "ASSERTION_AUDIENCE": "token_endpoint"}):
            self.assertEqual(self.finish().status_code, 302)

    def test_login_and_publication_check_with_inline_proxy_metadata(self):
        with override_settings(
            SOCA={**settings.SOCA, "METADATA_PROXY": "https://dynamic-cimd.resoauth.cloud/cimd/%s"}
        ):
            call_command("soca_check", stdout=io.StringIO())
            self.assertEqual(self.finish().status_code, 302)

    def test_check_and_cleanup_commands(self):
        output = io.StringIO()
        call_command("soca_check", stdout=output)
        self.assertIn("validated", output.getvalue())
        self.start()
        LoginTransaction.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        call_command("soca_cleanup", stdout=io.StringIO())
        self.assertEqual(LoginTransaction.objects.count(), 0)
