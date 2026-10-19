from django.urls import path

from . import views

app_name = "wagtail_soca"
urlpatterns = [
    path("client.json", views.metadata, name="metadata"),
    path("jwks.json", views.jwks, name="jwks"),
    path("login/", views.start, name="login"),
    path("callback/", views.callback, name="callback"),
]
