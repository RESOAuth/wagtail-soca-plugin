import io
import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from wagtail_soca import claim_inspection
from wagtail_soca.errors import SocaError
from wagtail_soca.models import ClaimInspection, SocaSettings

from .provider import ISSUER, Provider


class ClaimInspectionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        model = get_user_model()
        cls.admin = model.objects.create_superuser(
            username="admin", email="admin@example.com", password="test-password"
        )
        cls.editor = model.objects.create_user(username="editor", email="editor@example.com")
        cls.editor.user_permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )

    def setUp(self):
        self.url = reverse("wagtail_soca_settings")
        self.client.force_login(self.admin)
        self.provider = Provider()
        self.provider.overrides = {
            "preferred_username": "example.editor",
            "given_name": "Example",
            "family_name": "Editor",
            "name": "<script>alert('unsafe')</script>",
            "custom_secret": "must-not-be-retained",
            "sid": "provider-session-secret",
            "nested": {"access_token": "also-secret"},
        }
        self.provider.userinfo.update(preferred_username="userinfo.editor", locale="en-GB")
        self.transport = patch("wagtail_soca.http.request_json", side_effect=self.provider.fetch)
        self.mock_http = self.transport.start()
        self.addCleanup(self.transport.stop)

    def login_sso(self, **overrides):
        self.provider.overrides.update(overrides)
        client = Client()
        response = client.get("/soca/login/", secure=True)
        params = self.provider.authorize(response["Location"])
        return client.get("/soca/callback/", params, secure=True)

    def test_off_by_default_and_no_diagnostic_userinfo_request(self):
        self.provider.overrides.update(
            preferred_username="editor", given_name="Example", family_name="Editor"
        )
        self.assertContains(self.client.get(self.url, secure=True), "Temporary claim inspector")
        self.assertFalse(ClaimInspection.objects.exists())
        self.assertEqual(self.login_sso().status_code, 302)
        self.assertFalse(ClaimInspection.objects.exists())
        self.assertFalse(
            any(c.args[0] == ISSUER + "/userinfo" for c in self.mock_http.call_args_list)
        )

    def test_superuser_post_arm_and_clear_without_altering_settings(self):
        self.assertEqual(
            self.client.post(self.url, {"action": "inspect_arm"}, secure=True).status_code, 302
        )
        row = ClaimInspection.objects.get()
        self.assertFalse(row.payload)
        self.assertIsNone(row.captured_at)
        self.assertGreater(row.expires_at, timezone.now())
        self.assertFalse(SocaSettings.objects.exists())
        self.assertEqual(
            self.client.post(self.url, {"action": "inspect_clear"}, secure=True).status_code, 302
        )
        self.assertFalse(ClaimInspection.objects.exists())

    def test_non_superusers_cannot_read_arm_or_clear(self):
        claim_inspection.arm()
        for logged_in in (False, True):
            client = Client()
            if logged_in:
                client.force_login(self.editor)
            response = client.get(self.url, secure=True)
            self.assertIn(response.status_code, (302, 403))
            self.assertNotContains(
                response, "Temporary claim inspector", status_code=response.status_code
            )
            for action in ("inspect_arm", "inspect_clear"):
                old = ClaimInspection.objects.get().revision
                response = client.post(self.url, {"action": action}, secure=True)
                self.assertIn(response.status_code, (302, 403))
                self.assertEqual(ClaimInspection.objects.get().revision, old)

    def test_actions_require_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        for action in ("inspect_arm", "inspect_clear"):
            self.assertEqual(
                client.post(self.url, {"action": action}, secure=True).status_code, 403
            )
        self.assertFalse(ClaimInspection.objects.exists())

    def test_capture_verified_claims_encrypt_redact_and_escape_without_logging(self):
        claim_inspection.arm()
        with self.assertLogs("wagtail_soca", level="INFO") as logs:
            self.assertEqual(self.login_sso().status_code, 302)
        self.assertNotIn("example.editor", str(logs.output))
        row, report = claim_inspection.display()
        self.assertIsNotNone(row.captured_at)
        self.assertIn('"preferred_username": "example.editor"', report)
        self.assertIn('"preferred_username": "userinfo.editor"', report)
        self.assertIn('"userinfo_status": "subject matched"', report)
        self.assertNotIn("must-not-be-retained", report)
        self.assertNotIn("provider-session-secret", report)
        self.assertNotIn("also-secret", report)
        self.assertIn('"nonce": "[redacted]"', report)
        self.assertIn('"at_hash": "[redacted]"', report)
        self.assertNotIn("example.editor", row.payload)
        self.assertNotIn("fixture-access", row.payload)
        self.assertNotIn(
            "must-not-be-retained", claim_inspection.cipher().decrypt(row.payload.encode()).decode()
        )
        response = self.client.get(self.url, secure=True)
        self.assertContains(response, "example.editor")
        self.assertNotContains(response, "<script>alert('unsafe')</script>")
        self.assertContains(response, "&lt;script&gt;")
        self.assertIn("no-store", response["Cache-Control"])
        self.editor.refresh_from_db()
        self.assertEqual(self.editor.first_name, "Example")

    def test_failed_signature_or_admission_never_captures(self):
        claim_inspection.arm()
        for overrides in ({"nonce": "incorrect"}, {"email": "denied@other.example"}):
            self.provider.overrides.pop("nonce", None)
            self.assertEqual(self.login_sso(**overrides).status_code, 403)
            self.assertFalse(ClaimInspection.objects.get().payload)

    def test_userinfo_diagnostic_failure_or_wrong_subject_does_not_break_login(self):
        for failure in ("subject", "network"):
            claim_inspection.arm()
            if failure == "subject":
                self.provider.userinfo["sub"] = "different-person"
            else:
                original = self.provider.fetch

                def fetch(url, original=original, **kwargs):
                    if url == ISSUER + "/userinfo":
                        raise SocaError("http_failed")
                    return original(url, **kwargs)

                self.mock_http.side_effect = fetch
            self.assertEqual(self.login_sso().status_code, 302)
            _, report = claim_inspection.display()
            self.assertNotIn("userinfo.editor", report)
            self.assertIn(
                "userinfo_subject_mismatch" if failure == "subject" else "http_failed", report
            )

    def test_email_fallback_is_kept_distinct_from_signed_claims_and_fetches_once(self):
        claim_inspection.arm()
        self.provider.omit = {"email", "email_verified"}
        self.assertEqual(self.login_sso().status_code, 302)
        _, report = claim_inspection.display()
        data = json.loads(report)
        self.assertNotIn("email", data["id_token"])
        self.assertEqual(data["userinfo"]["email"], "editor@example.com")
        self.assertEqual(
            sum(c.args[0] == ISSUER + "/userinfo" for c in self.mock_http.call_args_list), 1
        )

    def test_one_shot_rearm_clear_and_stale_capture_cannot_overwrite(self):
        claim_inspection.arm()
        old = claim_inspection.pending()
        self.assertEqual(self.login_sso().status_code, 302)
        report = ClaimInspection.objects.get().payload
        self.assertEqual(self.login_sso(preferred_username="second").status_code, 302)
        self.assertEqual(ClaimInspection.objects.get().payload, report)
        claim_inspection.arm()
        claim_inspection.capture(old, {"id_token": {"name": "stale"}}, self.editor)
        self.assertFalse(ClaimInspection.objects.get().payload)
        pending = claim_inspection.pending()
        claim_inspection.clear()
        claim_inspection.capture(pending, {"id_token": {"name": "stale"}}, self.editor)
        self.assertFalse(ClaimInspection.objects.exists())

    def test_expiry_cleanup_and_corrupted_report_fail_closed(self):
        claim_inspection.arm()
        ClaimInspection.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(claim_inspection.pending())
        self.assertFalse(ClaimInspection.objects.exists())
        claim_inspection.arm()
        ClaimInspection.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        call_command("soca_cleanup", stdout=io.StringIO())
        self.assertFalse(ClaimInspection.objects.exists())
        claim_inspection.arm()
        ClaimInspection.objects.update(payload="corrupted")
        self.assertEqual(claim_inspection.display(), (None, ""))
        self.assertFalse(ClaimInspection.objects.exists())
