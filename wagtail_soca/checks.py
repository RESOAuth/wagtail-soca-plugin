from django.core.checks import Error, register

from .config import enabled, get_config
from .errors import SocaError


@register()
def check_soca(app_configs, **kwargs):
    # Deployment checks must work before the plugin's migrations have run.
    if enabled(use_database=False):
        try:
            get_config(use_database=False)
        except SocaError as exc:
            return [Error("SOCA configuration: " + str(exc), id="wagtail_soca.E001")]
    return []
