from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SECRET_KEY = "container-tests-only-not-a-deployment-secret"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "wagtail.example.com"]
ROOT_URLCONF = "tests.urls"
USE_TZ = True
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "TEST": {"NAME": "/tmp/soca-test.sqlite3"},
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
WAGTAIL_SITE_NAME = "SOCA tests"
WAGTAILADMIN_BASE_URL = "https://wagtail.example.com"
STATIC_URL = "/static/"
STATIC_ROOT = "/tmp/soca-static"
MEDIA_ROOT = "/tmp/soca-media"
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
    "BASE_URL": "https://wagtail.example.com",
    "ISSUER": "https://provider.example.com",
    "PRIVATE_KEY": ec.generate_private_key(ec.SECP256R1())
    .private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    .decode(),
    "ALLOW_DOMAINS": ["example.com"],
}
