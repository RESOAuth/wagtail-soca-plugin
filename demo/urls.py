from django.http import JsonResponse
from django.urls import include, path
from django.views.generic import RedirectView
from wagtail.admin import urls as admin_urls

urlpatterns = [
    path("", RedirectView.as_view(url="/admin/", permanent=False)),
    path("healthz/", lambda request: JsonResponse({"status": "ok", "mode": "local-demo"})),
    path("soca/", include("wagtail_soca.urls")),
    path("admin/", include(admin_urls)),
]
