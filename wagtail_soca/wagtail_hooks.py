from django.urls import path, reverse
from wagtail import hooks
from wagtail.admin.menu import AdminOnlyMenuItem

from .admin_views import settings_view


@hooks.register("register_admin_urls")
def register_admin_urls():
    return [path("soca/", settings_view, name="wagtail_soca_settings")]


@hooks.register("register_settings_menu_item")
def register_settings_menu_item():
    return AdminOnlyMenuItem(
        "SOCA", reverse("wagtail_soca_settings"), name="soca", icon_name="lock", order=600
    )
