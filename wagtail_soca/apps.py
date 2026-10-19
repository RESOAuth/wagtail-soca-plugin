from django.apps import AppConfig


class SocaConfig(AppConfig):
    name = "wagtail_soca"
    verbose_name = "Simple OAuth CIMD Access"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from . import checks  # noqa: F401
