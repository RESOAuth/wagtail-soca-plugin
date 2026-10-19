from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import Client, TestCase
from django.urls import reverse

from wagtail_soca import transactions
from wagtail_soca.config import get_config
from wagtail_soca.errors import SocaError
from wagtail_soca.models import SocaSettings
from wagtail_soca.protocol import resolve_user
from wagtail_soca.wagtail_hooks import register_settings_menu_item

from .provider import Provider


class AdminSettingsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_superuser(
            username="admin", email="admin@example.com", password="test-password"
        )
        cls.editor = get_user_model().objects.create_user(
            username="editor", email="editor@example.com", password="test-password"
        )
        cls.editor.user_permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )

    def setUp(self):
        self.url = reverse("wagtail_soca_settings")
        self.client.force_login(self.admin)

    def data(self, **changes):
        row = SocaSettings.objects.filter(pk=1).first()
        return {
            "action": "save",
            "revision": str(row.revision) if row else "",
            "enabled": "on",
            "issuer": "https://auth.resoauth.cloud",
            "metadata_mode": "proxy",
            "metadata_proxy": "https://dynamic-cimd.resoauth.cloud/cimd/%s",
            "id_token_alg": "ES256",
            "assertion_audience": "issuer",
            "allow_emails": "editor@example.com",
            "allow_domains": "",
            "deny_emails": "",
            "deny_domains": "",
            **changes,
        }

    def test_menu_is_in_settings_and_requires_superuser(self):
        item = register_settings_menu_item()
        self.assertEqual(item.label, "SOCA")
        self.assertEqual(item.url, self.url)
        self.assertTrue(item.is_shown(SimpleNamespace(user=self.admin)))
        self.assertFalse(item.is_shown(SimpleNamespace(user=self.editor)))
        response = self.client.get("/admin/", secure=True)
        self.assertContains(response, self.url)

    def test_form_shows_defaults_account_guidance_and_no_private_key(self):
        response = self.client.get(self.url, secure=True)
        self.assertContains(response, "Access rules")
        self.assertContains(response, "Connection check")
        self.assertContains(response, "admin@example.com")
        self.assertContains(response, "/soca/callback/")
        self.assertContains(response, reverse("wagtailusers_users:edit", args=[self.admin.pk]))
        self.assertNotContains(response, settings.SOCA["PRIVATE_KEY"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertFalse(SocaSettings.objects.exists())

    def test_anonymous_and_editor_cannot_view_or_save(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url, secure=True).status_code, 302)
        self.client.force_login(self.editor)
        for response in (
            self.client.get(self.url, secure=True),
            self.client.post(self.url, self.data(), secure=True),
        ):
            # Wagtail's permission-denied handler sends editors back to their dashboard.
            self.assertIn(response.status_code, (302, 403))
            if response.status_code == 302:
                self.assertEqual(response["Location"], reverse("wagtailadmin_home"))
        self.assertFalse(SocaSettings.objects.exists())

    def test_save_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post(self.url, self.data(), secure=True).status_code, 403)
        self.assertFalse(SocaSettings.objects.exists())
        client.get(self.url, secure=True)
        data = self.data(csrfmiddlewaretoken=client.cookies["csrftoken"].value)
        self.assertEqual(
            client.post(
                self.url, data, secure=True, HTTP_REFERER="https://testserver" + self.url
            ).status_code,
            302,
        )

    def test_save_applies_immediately_and_stores_no_secrets(self):
        data = self.data(allow_emails="EDITOR@example.com, second@example.com\nEDITOR@example.com")
        data["PRIVATE_KEY"] = "attacker-supplied-key"
        self.assertRedirects(
            self.client.post(self.url, data, secure=True), self.url, fetch_redirect_response=False
        )
        row = SocaSettings.objects.get()
        self.assertEqual(row.values["ALLOW_EMAILS"], ["editor@example.com", "second@example.com"])
        self.assertEqual(row.updated_by, self.admin)
        self.assertNotIn("PRIVATE_KEY", row.values)
        self.assertNotIn("BASE_URL", row.values)
        config = get_config()
        self.assertEqual(config.issuer, "https://auth.resoauth.cloud")
        self.assertEqual(config.revision, str(row.revision))
        self.assertEqual(
            resolve_user(config, {"email": "editor@example.com", "email_verified": True}),
            self.editor,
        )
        self.assertContains(self.client.get(self.url, secure=True), "second@example.com")

    def test_account_creation_requires_eligible_group_and_is_opt_in(self):
        response = self.client.get(self.url, secure=True)
        self.assertContains(response, "Create accounts on first SSO login")
        self.assertFalse(response.context["form"].initial["create_users"])
        self.assertEqual(
            self.client.post(self.url, self.data(create_users="on"), secure=True).status_code,
            400,
        )
        group = Group.objects.create(name="No admin access")
        self.assertEqual(
            self.client.post(
                self.url, self.data(create_users="on", new_user_group=group.pk), secure=True
            ).status_code,
            400,
        )
        self.assertFalse(SocaSettings.objects.exists())
        group.permissions.add(self.editor.user_permissions.get())
        self.assertEqual(
            self.client.post(
                self.url, self.data(create_users="on", new_user_group=group.pk), secure=True
            ).status_code,
            302,
        )
        self.assertTrue(get_config().create_users)
        self.assertEqual(get_config().new_user_group, group.pk)
        self.assertTrue(
            self.client.get(self.url, secure=True).context["form"].initial["create_users"]
        )
        self.client.post(self.url, self.data(new_user_group=group.pk), secure=True)
        self.assertFalse(get_config().create_users)

    def test_bad_values_are_not_saved(self):
        for changes in (
            {"issuer": "http://example.com"},
            {"allow_domains": "*.example.com"},
            {"allow_emails": "not-an-email"},
            {"metadata_proxy": "https://%s.example.com/"},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    self.client.post(self.url, self.data(**changes), secure=True).status_code, 400
                )
                self.assertFalse(SocaSettings.objects.exists())

    def test_disable_sso_keeps_password_login_and_settings_available(self):
        self.assertEqual(
            self.client.post(self.url, self.data(enabled=""), secure=True).status_code, 302
        )
        self.client.logout()
        self.assertNotContains(self.client.get("/admin/login/", secure=True), "Continue with SSO")
        self.assertEqual(
            self.client.post(
                "/admin/login/",
                {
                    "username": "admin",
                    "password": "test-password",
                    "next": self.url,
                },
                secure=True,
            ).status_code,
            302,
        )
        self.assertContains(self.client.get(self.url, secure=True), "SSO disabled")

    def test_empty_allow_lists_are_explained_and_deny_access(self):
        self.client.post(self.url, self.data(allow_emails=""), secure=True)
        self.assertContains(
            self.client.get(self.url, secure=True), "No email addresses or domains are allowed"
        )
        with self.assertRaises(SocaError):
            resolve_user(get_config(), {"email": "editor@example.com", "email_verified": True})

    def test_stale_settings_form_cannot_overwrite_new_values(self):
        first = self.data()
        self.client.post(self.url, first, secure=True)
        response = self.client.post(self.url, first, secure=True)
        self.assertContains(response, "Another administrator changed", status_code=400)
        old = self.data()
        self.client.post(self.url, self.data(allow_emails="new@example.com"), secure=True)
        self.assertEqual(self.client.post(self.url, old, secure=True).status_code, 400)
        self.assertEqual(SocaSettings.objects.get().values["ALLOW_EMAILS"], ["new@example.com"])

    def test_save_invalidates_pending_login_even_if_configuration_returns_to_old_values(self):
        request = SimpleNamespace(session={})
        config = get_config()
        state, _ = transactions.begin(request, config, Provider().document, "/admin/")
        self.client.post(self.url, self.data(), secure=True)
        with self.assertRaisesMessage(SocaError, "configuration_changed"):
            transactions.consume(request, get_config(), state)

    def test_saved_database_cannot_override_deployment_secrets_or_origin(self):
        SocaSettings.objects.create(
            pk=1,
            values={
                "PRIVATE_KEY": "untrusted",
                "BASE_URL": "https://evil.example.com",
            },
        )
        self.assertEqual(get_config().base_url, settings.SOCA["BASE_URL"])

    def test_connection_check_is_post_only_and_redacts_provider_errors(self):
        provider = Provider()
        with patch("wagtail_soca.http.request_json", side_effect=provider.fetch):
            response = self.client.post(self.url, {"action": "check"}, secure=True, follow=True)
        self.assertContains(
            response, "Provider discovery, client metadata and public key validated"
        )
        self.assertFalse(SocaSettings.objects.exists())
        with patch("wagtail_soca.http.request_json", side_effect=SocaError("http_failed")):
            response = self.client.post(self.url, {"action": "check"}, secure=True, follow=True)
        self.assertContains(response, "Connection check failed (http_failed)")
