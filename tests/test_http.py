import socket
from unittest import TestCase
from unittest.mock import MagicMock, patch

from wagtail_soca.errors import SocaError
from wagtail_soca.http import MAX_BODY, public_addresses, request_json, validate_url


class TransportTests(TestCase):
    def test_unsafe_urls(self):
        for url in (
            "http://provider.example.com",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://user:pass@example.com/",
            "https://example.com/#x",
            "https://example.com/a/../b",
            "https://example.com/%2e%2e/",
            "https://example.com/\r\nHeader: bad",
            "https://exämple.com/",
            "https://evil\\.example.com/",
        ):
            with self.subTest(url=url), self.assertRaises(SocaError):
                validate_url(url)

    def test_dns_rejects_private_mixed_and_mapped_addresses(self):
        for addresses in (
            ["127.0.0.1"],
            ["10.0.0.1"],
            ["169.254.169.254"],
            ["::1"],
            ["8.8.8.8", "192.168.1.1"],
            ["::ffff:8.8.8.8"],
            ["224.0.0.1"],
        ):
            resolved = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (x, 443)) for x in addresses]
            with (
                self.subTest(addresses=addresses),
                patch("socket.getaddrinfo", return_value=resolved),
                self.assertRaises(SocaError),
            ):
                public_addresses("provider.example.com", 443)

    @patch("wagtail_soca.http.public_addresses", return_value=["8.8.8.8"])
    @patch("urllib3.HTTPSConnectionPool")
    def test_pinned_tls_host_no_redirect_and_bounded_body(self, pool, dns):
        response = MagicMock(status=200, headers={"Content-Type": "application/json"})
        response.read.return_value = b'{"ok": true}'
        pool.return_value.urlopen.return_value = response
        self.assertEqual(
            request_json("https://provider.example.com:8443/token", form={"code": "private"}),
            {"ok": True},
        )
        self.assertEqual(pool.call_args.args[0], "8.8.8.8")
        self.assertEqual(pool.call_args.kwargs["server_hostname"], "provider.example.com")
        self.assertEqual(pool.call_args.kwargs["assert_hostname"], "provider.example.com")
        args = pool.return_value.urlopen.call_args.kwargs
        self.assertFalse(args["redirect"])
        self.assertEqual(args["headers"]["Host"], "provider.example.com:8443")
        response.read.assert_called_once_with(MAX_BODY + 1, decode_content=False)
        for status, headers, body in (
            (302, {"Content-Type": "application/json"}, b"{}"),
            (200, {"Content-Type": "text/html"}, b"{}"),
            (200, {"Content-Type": "application/json"}, b"x" * (MAX_BODY + 1)),
            (200, {"Content-Type": "application/json"}, b"[]"),
            (200, {"Content-Type": "application/json"}, b'{"same": 1, "same": 2}'),
            (200, {"Content-Type": "application/json"}, b'{"number": Infinity}'),
            (200, {"Content-Type": "application/json", "Content-Encoding": "gzip"}, b"{}"),
        ):
            response.status, response.headers, response.read.return_value = status, headers, body
            with self.subTest(status=status, headers=headers), self.assertRaises(SocaError):
                request_json("https://provider.example.com/doc")
