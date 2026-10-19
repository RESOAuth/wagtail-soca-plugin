from django.urls import include, path
from wagtail.admin import urls as admin_urls

urlpatterns = [
    path("soca/", include("wagtail_soca.urls")),
    path("admin/", include(admin_urls)),
]
