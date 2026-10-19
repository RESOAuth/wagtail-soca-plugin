from dataclasses import replace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase, override_settings

from wagtail_soca.config import get_config
from wagtail_soca.errors import SocaError
from wagtail_soca.protocol import resolve_user
from wagtail_soca.provisioning import provisioning_fields

from .provider import Provider


class ProvisioningTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.group = Group.objects.create(name="SSO members")
        cls.group.permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )

    def setUp(self):
        self.config = replace(get_config(), create_users=True, new_user_group=self.group.pk)
        self.claims = {"email": "NEW@example.com", "email_verified": True}

    def test_default_off_does_not_create_accounts(self):
        with self.assertRaisesMessage(SocaError, "account_missing_or_ambiguous"):
            resolve_user(get_config(), self.claims)
        self.assertFalse(get_user_model().objects.exists())

    def test_created_user_has_only_selected_group_and_no_local_password(self):
        user = resolve_user(self.config, {**self.claims, "is_superuser": True, "roles": ["admin"]})
        user.refresh_from_db()
        self.assertEqual(user.email, "new@example.com")
        self.assertEqual(list(user.groups.all()), [self.group])
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.has_usable_password())
        self.assertFalse(user.user_permissions.exists())
        self.assertTrue(user.is_active)
        self.assertTrue(user.has_perm("wagtailadmin.access_admin"))
        self.assertEqual(resolve_user(self.config, self.claims).pk, user.pk)
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_unverified_or_unadmitted_emails_cannot_create_users(self):
        for claims in (
            {**self.claims, "email_verified": False},
            {**self.claims, "email_verified": "true"},
            {**self.claims, "email": "new@other.example"},
            {**self.claims, "email": "invalid"},
        ):
            with self.subTest(claims=claims), self.assertRaises(SocaError):
                resolve_user(self.config, claims)
        for config in (
            replace(self.config, deny_emails=("new@example.com",)),
            replace(self.config, deny_domains=("example.com",)),
            replace(self.config, allow_domains=()),
        ):
            with self.assertRaisesMessage(SocaError, "admission_denied"):
                resolve_user(config, self.claims)
        self.assertFalse(get_user_model().objects.exists())

    def test_missing_or_no_longer_eligible_group_fails_closed(self):
        self.group.permissions.clear()
        for group_id in (None, self.group.pk, 999999):
            with self.subTest(group_id=group_id), self.assertRaises(SocaError):
                resolve_user(replace(self.config, new_user_group=group_id), self.claims)
        self.assertFalse(get_user_model().objects.exists())

    def test_existing_accounts_are_never_promoted_or_reenabled(self):
        user = get_user_model().objects.create_user(
            username="existing", email="new@example.com", password="existing-password"
        )
        for active in (True, False):
            user.is_active = active
            user.save()
            with self.assertRaisesMessage(SocaError, "account_ineligible"):
                resolve_user(self.config, self.claims)
        user.refresh_from_db()
        self.assertFalse(user.groups.exists())
        self.assertFalse(user.is_active)
        self.assertTrue(user.check_password("existing-password"))

    def test_existing_eligible_account_keeps_its_group_and_password(self):
        user = get_user_model().objects.create_user(
            username="existing", email="new@example.com", password="existing-password"
        )
        user.user_permissions.add(self.group.permissions.get())
        self.assertEqual(resolve_user(self.config, self.claims).pk, user.pk)
        self.assertFalse(user.groups.exists())
        self.assertTrue(user.check_password("existing-password"))

    def test_duplicate_email_and_username_collision_are_rejected(self):
        model = get_user_model()
        collision = model.objects.create_user(
            username=provisioning_fields("new@example.com")[model.USERNAME_FIELD],
            email="other@example.com",
        )
        with self.assertRaisesMessage(SocaError, "account_creation_conflict"):
            resolve_user(self.config, self.claims)
        self.assertEqual(model.objects.count(), 1)
        collision.email = "new@example.com"
        collision.save()
        model.objects.create_user(username="duplicate", email="NEW@example.com")
        with self.assertRaisesMessage(SocaError, "account_missing_or_ambiguous"):
            resolve_user(self.config, self.claims)
        self.assertEqual(model.objects.count(), 2)

    def test_failed_group_assignment_rolls_back_account(self):
        model = get_user_model()
        with (
            patch.object(model, "has_perm", return_value=False),
            self.assertRaisesMessage(SocaError, "account_ineligible"),
        ):
            resolve_user(self.config, self.claims)
        self.assertFalse(model.objects.exists())

    def test_unsupported_custom_required_fields_fail_closed(self):
        model = get_user_model()
        with (
            patch.object(model, "REQUIRED_FIELDS", ["email", "organisation"]),
            self.assertRaisesMessage(SocaError, "unsupported_provisioning_user_model"),
        ):
            resolve_user(self.config, self.claims)
        self.assertFalse(model.objects.exists())

    def test_provisioning_changes_invalidate_pending_logins_not_public_metadata(self):
        original = get_config()
        self.assertNotEqual(original.fingerprint, self.config.fingerprint)
        self.assertNotEqual(
            self.config.fingerprint,
            replace(self.config, new_user_group=self.group.pk + 1).fingerprint,
        )
        self.assertEqual(original.document(), self.config.document())

    def test_full_signed_callback_creates_and_signs_in_new_account(self):
        provider = Provider()
        provider.overrides = {"email": "new@example.com"}
        with (
            override_settings(
                SOCA={**settings.SOCA, "CREATE_USERS": True, "NEW_USER_GROUP": self.group.pk}
            ),
            patch("wagtail_soca.http.request_json", side_effect=provider.fetch),
        ):
            start = self.client.get("/soca/login/", secure=True)
            params = provider.authorize(start["Location"])
            response = self.client.get("/soca/callback/", params, secure=True)
        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.get(email="new@example.com")
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))
        self.assertEqual(self.client.get("/admin/", secure=True).status_code, 200)
