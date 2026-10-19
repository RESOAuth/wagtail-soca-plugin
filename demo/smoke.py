"""Run against the live container: podman exec wagtail-soca-demo python -m demo.smoke."""

import http.client
import re
import ssl
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import requests

from wagtail_soca import http as soca_http

ORIGIN = "https://wagtail.localhost:8443"


class LiveDemoTests(unittest.TestCase):
    def setUp(self):
        self.cookies = {}
        self.context = ssl.create_default_context(cafile="/data/tls.pem")

    def request(self, target, form=None):
        parsed = urlsplit(target)
        self.assertIn(parsed.netloc, ("", "wagtail.localhost:8443"))
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection = http.client.HTTPSConnection(
            "127.0.0.1", 8443, context=self.context, timeout=10
        )
        headers = {
            "Host": "wagtail.localhost:8443",
            "Cookie": "; ".join(name + "=" + value for name, value in self.cookies.items()),
        }
        if form is not None:
            headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": ORIGIN,
                    "Referer": ORIGIN + path,
                }
            )
        try:
            connection.request(
                "GET" if form is None else "POST",
                path,
                body=None if form is None else urlencode(form),
                headers=headers,
            )
            response = connection.getresponse()
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    cookie = SimpleCookie()
                    cookie.load(value)
                    self.cookies.update({key: item.value for key, item in cookie.items()})
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def csrf(self, body):
        match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', body)
        self.assertIsNotNone(match)
        return match[1]

    def test_health_and_static(self):
        self.assertEqual(self.request("/healthz/")[0], 200)
        self.assertEqual(self.request("/static/wagtailadmin/css/core.css")[0], 200)

    def test_local_password_login(self):
        status, _, body = self.request("/admin/login/")
        self.assertEqual(status, 200)
        status, _, _ = self.request(
            "/admin/login/",
            {
                "username": "admin",
                "password": Path("/data/admin-password").read_text(),
                "csrfmiddlewaretoken": self.csrf(body),
                "next": "/admin/",
            },
        )
        self.assertEqual(status, 302)
        self.assertEqual(self.request("/admin/")[0], 200)

    def test_real_provider_redirect_and_published_metadata(self):
        status, headers, _ = self.request("/soca/login/?next=/admin/")
        self.assertEqual(status, 302)
        provider_url = headers["Location"]
        self.assertEqual(urlsplit(provider_url).netloc, "auth.resoauth.cloud")
        self.assertEqual(urlsplit(provider_url).path, "/authorize")
        params = parse_qs(urlsplit(provider_url).query)
        self.assertEqual(params["redirect_uri"], [ORIGIN + "/soca/callback/"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertTrue(
            params["client_id"][0].startswith("https://dynamic-cimd.resoauth.cloud/cimd/")
        )
        metadata = soca_http.request_json(params["client_id"][0])
        self.assertEqual(metadata["client_id"], params["client_id"][0])
        self.assertEqual(metadata["redirect_uris"], [ORIGIN + "/soca/callback/"])
        self.assertNotIn("d", metadata["jwks"]["keys"][0])
        response = requests.get(provider_url, timeout=20, allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Sign in", response.text)
        self.assertIn("email", response.text.lower())

    def test_old_stub_route_is_gone(self):
        self.assertEqual(self.request("/provider/authorize/")[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
