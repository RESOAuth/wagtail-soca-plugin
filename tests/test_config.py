from django.conf import settings
from django.core.checks import run_checks
from django.test import TestCase, override_settings

from wagtail_soca.config import get_config
from wagtail_soca.errors import SocaError


class ConfigTests(TestCase):
    def test_bad_configuration(self):
        for change in (
            {"BASE_URL": "http://example.com"},
            {"BASE_URL": "https://example.com/"},
            {"PRIVATE_KEY": "invalid"},
            {"PRIVATE_KEY": None},
            {"ID_TOKEN_ALG": "HS256"},
            {"ALLOW_DOMAINS": "example.com"},
            {"ALLOW_DOMAINS": ["*.example.com"]},
            {"ISSUER": "https://example.com?x=y"},
            {"CREATE_USERS": "true"},
            {"CREATE_USERS": True},
            {"NEW_USER_GROUP": True},
            {"NEW_USER_GROUP": -1},
        ):
            with (
                self.subTest(change=change),
                override_settings(SOCA={**settings.SOCA, **change}),
                self.assertRaises(SocaError),
            ):
                get_config()

    def test_unsafe_session_or_backend_configuration(self):
        for change in (
            {"SESSION_ENGINE": "django.contrib.sessions.backends.signed_cookies"},
            {"SESSION_COOKIE_SECURE": False},
            {"SESSION_COOKIE_SAMESITE": "Strict"},
            {"SESSION_COOKIE_HTTPONLY": False},
            {"AUTHENTICATION_BACKENDS": []},
        ):
            with (
                self.subTest(change=change),
                override_settings(**change),
                self.assertRaises(SocaError),
            ):
                get_config()

    def test_system_check_reports_invalid_config_without_secret(self):
        with override_settings(SOCA={**settings.SOCA, "PRIVATE_KEY": "private-secret-not-pem"}):
            errors = [x for x in run_checks() if x.id == "wagtail_soca.E001"]
        self.assertEqual(len(errors), 1)
        self.assertNotIn("private-secret", str(errors))
