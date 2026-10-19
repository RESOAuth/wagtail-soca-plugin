import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db import connections
from django.db.models.query import QuerySet
from django.test import TransactionTestCase

from wagtail_soca import provisioning, transactions
from wagtail_soca.config import get_config
from wagtail_soca.errors import SocaError
from wagtail_soca.models import LoginTransaction
from wagtail_soca.protocol import resolve_user

from .provider import Provider


class ConcurrentCallbackTests(TransactionTestCase):
    def test_simultaneous_first_logins_create_one_account(self):
        group = Group.objects.create(name="SSO members")
        group.permissions.add(
            Permission.objects.get(content_type__app_label="wagtailadmin", codename="access_admin")
        )
        config = replace(get_config(), create_users=True, new_user_group=group.pk)
        barrier = threading.Barrier(2)
        original_matches = provisioning.matching_users

        def synchronized_matches(email):
            matches = original_matches(email)
            if not matches:
                barrier.wait(timeout=5)
            return matches

        def worker(index):
            try:
                return resolve_user(
                    config,
                    {
                        "email": "new@example.com",
                        "email_verified": True,
                        "preferred_username": f"preferred-{index}",
                    },
                ).pk
            finally:
                connections.close_all()

        with (
            patch("wagtail_soca.protocol.matching_users", side_effect=synchronized_matches),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            results = list(pool.map(worker, range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertIn(get_user_model().objects.get().username, ("preferred-0", "preferred-1"))

    def test_only_one_worker_can_consume_the_same_transaction(self):
        request = SimpleNamespace(session={})
        config = get_config()
        state, _ = transactions.begin(request, config, Provider().document, "/admin/")
        barrier = threading.Barrier(2)
        original_first = QuerySet.first

        def synchronized_first(query):
            row = original_first(query)
            if query.model is LoginTransaction:
                barrier.wait(timeout=5)
            return row

        def worker():
            try:
                transactions.consume(request, config, state)
                return "accepted"
            except SocaError:
                return "refused"
            finally:
                connections.close_all()

        # Force both workers to read the unconsumed row before either claims it.
        with (
            patch.object(QuerySet, "first", synchronized_first),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            results = list(pool.map(lambda _: worker(), range(2)))
        self.assertCountEqual(results, ["accepted", "refused"])
