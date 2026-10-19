from dataclasses import replace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase, override_settings

from wagtail_soca.config import digest, get_config
from wagtail_soca.errors import SocaError
from wagtail_soca.profiles import fill_names
from wagtail_soca.protocol import resolve_user

from .provider import ISSUER, Provider


class ProfileTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.group = Group.objects.create(name="SSO members")
        cls.group.permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )

    def setUp(self):
        self.model = get_user_model()
        self.config = replace(get_config(), create_users=True, new_user_group=self.group.pk)
        self.claims = {
            "email": "editor@example.com",
            "email_verified": True,
            "given_name": "Ollie",
            "family_name": "Chalk",
            "name": "Ollie Chalk",
        }

    def test_structured_names_and_readable_fallback_without_preferred_username(self):
        user = resolve_user(self.config, self.claims)
        self.assertEqual((user.first_name, user.last_name), ("Ollie", "Chalk"))
        self.assertEqual(user.username, "editor_" + digest("editor@example.com")[:12])
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.has_usable_password())

    def test_valid_preferred_username_for_new_users(self):
        user = resolve_user(self.config, {**self.claims, "preferred_username": "ollie.chalk"})
        self.assertEqual(user.username, "ollie.chalk")

    def test_colliding_preferred_username_never_selects_or_changes_another_account(self):
        existing = self.model.objects.create_user(username="OLLIE", email="different@example.com")
        user = resolve_user(self.config, {**self.claims, "preferred_username": "ollie"})
        self.assertNotEqual(user.pk, existing.pk)
        self.assertEqual(user.username, "editor_" + digest("editor@example.com")[:12])
        existing.refresh_from_db()
        self.assertEqual(existing.first_name, "")
        self.assertEqual(existing.email, "different@example.com")

    def test_invalid_missing_reserved_or_long_preferred_username_uses_safe_fallback(self):
        for value in (
            None,
            {},
            5,
            "",
            "<script>",
            "spaces are invalid",
            "x" * 151,
            "soca_reserved",
        ):
            with self.subTest(value=value):
                user = resolve_user(self.config, {**self.claims, "preferred_username": value})
                self.assertEqual(user.username, "editor_" + digest("editor@example.com")[:12])
                user.delete()

    def test_fallback_collision_retains_deterministic_hashed_identifier(self):
        fallback = "editor_" + digest("editor@example.com")[:12]
        self.model.objects.create_user(username=fallback, email="other@example.com")
        user = resolve_user(self.config, self.claims)
        self.assertEqual(user.username, "soca_" + digest("editor@example.com"))

    def test_existing_blank_names_filled_but_identity_password_and_privileges_unchanged(self):
        user = self.model.objects.create_superuser(
            username="admin", email="editor@example.com", password="local-password"
        )
        password = user.password
        result = resolve_user(self.config, {**self.claims, "preferred_username": "rename-me"})
        self.assertEqual(result.pk, user.pk)
        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ("Ollie", "Chalk"))
        self.assertEqual(user.username, "admin")
        self.assertEqual(user.email, "editor@example.com")
        self.assertEqual(user.password, password)
        self.assertTrue(user.is_superuser)
        self.assertFalse(user.groups.exists())

    def test_local_name_edits_preserved_and_only_blank_fields_filled(self):
        user = resolve_user(self.config, self.claims)
        user.first_name, user.last_name = "Local first", ""
        user.save()
        result = resolve_user(self.config, self.claims)
        self.assertEqual((result.first_name, result.last_name), ("Local first", "Chalk"))
        # A stale instance must not overwrite a concurrent local edit.
        result.last_name = ""
        self.model.objects.filter(pk=user.pk).update(last_name="Local surname")
        fill_names(result, self.claims)
        user.refresh_from_db()
        self.assertEqual(user.last_name, "Local surname")

    def test_full_name_fallback_does_not_guess_surname_or_duplicate_local_parts(self):
        claims = {
            "email": "editor@example.com",
            "email_verified": True,
            "name": "Mary Ann van der Meer",
        }
        user = resolve_user(self.config, claims)
        self.assertEqual((user.first_name, user.last_name), ("Mary Ann van der Meer", ""))
        user.first_name, user.last_name = "", "Local surname"
        user.save()
        result = resolve_user(self.config, claims)
        self.assertEqual((result.first_name, result.last_name), ("", "Local surname"))

    def test_unicode_whitespace_lengths_and_invalid_types_handled_conservatively(self):
        user = resolve_user(
            self.config,
            {**self.claims, "given_name": "  Jose\u0301   María ", "family_name": "界" * 200},
        )
        self.assertEqual(user.first_name, "José María")
        self.assertEqual(user.last_name, "界" * 150)
        user.delete()
        for value in (None, {}, 42, "<img src=x>", "hidden\u202ename", "x" * 4097):
            with self.subTest(value_type=type(value).__name__):
                user = resolve_user(
                    self.config,
                    {**self.claims, "given_name": value, "family_name": value, "name": value},
                )
                self.assertEqual((user.first_name, user.last_name), ("", ""))
                user.delete()

    def test_failed_admission_and_ineligible_users_are_not_updated(self):
        user = self.model.objects.create_user(username="editor", email="editor@example.com")
        for config, claims in (
            (self.config, self.claims),
            (replace(self.config, allow_domains=()), self.claims),
            (self.config, {**self.claims, "email_verified": False}),
        ):
            with self.assertRaises(SocaError):
                resolve_user(config, claims)
        user.refresh_from_db()
        self.assertEqual((user.first_name, user.last_name), ("", ""))

    def signed_login(self, provider):
        with (
            override_settings(
                SOCA={**settings.SOCA, "CREATE_USERS": True, "NEW_USER_GROUP": self.group.pk}
            ),
            patch("wagtail_soca.http.request_json", side_effect=provider.fetch) as transport,
        ):
            start = self.client.get("/soca/login/", secure=True)
            response = self.client.get(
                "/soca/callback/", provider.authorize(start["Location"]), secure=True
            )
        self.assertEqual(response.status_code, 302)
        return self.model.objects.get(email="editor@example.com"), transport

    def test_subject_matched_userinfo_supplies_missing_profile_outside_inspector(self):
        provider = Provider()
        provider.userinfo.update(
            given_name="Ollie", family_name="Chalk", preferred_username="ollie"
        )
        user, transport = self.signed_login(provider)
        self.assertEqual(
            (user.first_name, user.last_name, user.username), ("Ollie", "Chalk", "ollie")
        )
        self.assertEqual(
            sum(c.args[0] == ISSUER + "/userinfo" for c in transport.call_args_list), 1
        )

    def test_signed_claims_take_priority_and_complete_profile_needs_no_userinfo(self):
        provider = Provider()
        provider.overrides.update(self.claims, preferred_username="signed")
        provider.userinfo.update(given_name="Conflicting", family_name="Other")
        user, transport = self.signed_login(provider)
        self.assertEqual(
            (user.first_name, user.last_name, user.username), ("Ollie", "Chalk", "signed")
        )
        self.assertFalse(any(c.args[0] == ISSUER + "/userinfo" for c in transport.call_args_list))

    def test_mismatched_userinfo_is_not_used_for_names_or_account_selection(self):
        for mismatch in (
            {"sub": "other-person"},
            {"email": "other@example.com"},
            {"email_verified": False},
        ):
            provider = Provider()
            provider.userinfo.update(given_name="Wrong", preferred_username="wrong", **mismatch)
            user, _ = self.signed_login(provider)
            self.assertEqual((user.first_name, user.last_name), ("", ""))
            self.assertNotEqual(user.username, "wrong")
            user.delete()
            self.client.logout()

    def test_optional_profile_fetch_failure_does_not_break_valid_login(self):
        provider = Provider()
        original = provider.fetch

        def fetch(url, **kwargs):
            if url == ISSUER + "/userinfo":
                raise SocaError("http_failed")
            return original(url, **kwargs)

        with patch.object(provider, "fetch", side_effect=fetch):
            user, _ = self.signed_login(provider)
        self.assertEqual((user.first_name, user.last_name), ("", ""))

    def test_custom_unique_name_field_is_not_treated_as_a_profile_default(self):
        field = self.model._meta.get_field("first_name")
        with patch.object(field, "unique", True):
            user = resolve_user(self.config, self.claims)
        self.assertEqual(user.first_name, "")
        self.assertEqual(user.last_name, "Chalk")
