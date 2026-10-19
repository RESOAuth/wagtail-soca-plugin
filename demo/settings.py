from pathlib import Path

DATA_DIR = Path("/data")
BASE_URL = "https://wagtail.localhost:8443"
SECRET_KEY = (DATA_DIR / "django-secret").read_text()
DEBUG = False
ALLOWED_HOSTS = ["wagtail.localhost", "localhost", "127.0.0.1"]
ROOT_URLCONF = "demo.urls"
USE_TZ = True
TIME_ZONE = "Europe/London"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": DATA_DIR / "db.sqlite3"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = [BASE_URL]
WAGTAIL_SITE_NAME = "SOCA local demo"
WAGTAILADMIN_BASE_URL = BASE_URL
STATIC_URL = "/static/"
MEDIA_ROOT = DATA_DIR / "media"
MEDIA_URL = "/media/"
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
INSTALLED_APPS = [
    "wagtail_soca",
    "wagtail.contrib.forms",
    "wagtail.contrib.redirects",
    "wagtail.embeds",
    "wagtail.sites",
    "wagtail.users",
    "wagtail.snippets",
    "wagtail.documents",
    "wagtail.images",
    "wagtail.search",
    "wagtail.admin",
    "wagtail",
    "modelcluster",
    "taggit",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
SOCA = {
    "ENABLED": True,
    "BASE_URL": BASE_URL,
    "ISSUER": "https://auth.resoauth.cloud",
    "PRIVATE_KEY": (DATA_DIR / "soca.pem").read_text(),
    "METADATA_PROXY": "https://dynamic-cimd.resoauth.cloud/cimd/%s",
    "ALLOW_EMAILS": [(DATA_DIR / "admin-email").read_text().strip()]
    if (DATA_DIR / "admin-email").exists()
    else [],
}
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"console": {"format": "{asctime} {levelname} {name}: {message}", "style": "{"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "console"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"django": {"handlers": ["console"], "level": "INFO", "propagate": False}},
}
