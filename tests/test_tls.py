"""Exercise the actual pinned urllib3 transport over loopback with a test-only CA."""

import json
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wagtail_soca.errors import SocaError
from wagtail_soca.http import request_json


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({"host": self.headers["Host"]}).encode()
        self.send_response(302 if self.path == "/redirect" else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        response = json.dumps(parse_qs(body.decode())).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class FixtureServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Intentional client-side TLS/redirect rejection may close the socket early.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class TLSTransportTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.TemporaryDirectory()
        cls.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "provider.example.com")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(cls.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("provider.example.com")]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.key, hashes.SHA256())
        )
        cert_file = Path(cls.directory.name) / "ca.pem"
        key_file = Path(cls.directory.name) / "key.pem"
        cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            cls.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file, key_file)
        cls.sni = []
        context.set_servername_callback(lambda sock, server_name, ctx: cls.sni.append(server_name))
        cls.server = FixtureServer(("127.0.0.1", 0), Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client_context = ssl.create_default_context(cafile=str(cert_file))
        cls.origin = "https://provider.example.com:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.directory.cleanup()
        super().tearDownClass()

    @patch("wagtail_soca.http.public_addresses", return_value=["127.0.0.1"])
    def test_real_https_get_post_sni_and_redirect_refusal(self, addresses):
        with patch(
            "wagtail_soca.http.ssl.create_default_context", return_value=self.client_context
        ):
            self.assertEqual(
                request_json(self.origin + "/"), {"host": self.origin.removeprefix("https://")}
            )
            self.assertEqual(
                request_json(self.origin + "/token", form={"code": "a+b &c"}), {"code": ["a+b &c"]}
            )
            with self.assertRaises(SocaError):
                request_json(self.origin + "/redirect")
        self.assertIn("provider.example.com", self.sni)

    def test_server_requires_tls12_or_newer(self):
        self.assertGreaterEqual(self.server.socket.context.minimum_version, ssl.TLSVersion.TLSv1_2)

    @patch("wagtail_soca.http.public_addresses", return_value=["127.0.0.1"])
    def test_untrusted_certificate_and_wrong_hostname_refused(self, addresses):
        with self.assertRaises(SocaError):
            request_json(self.origin + "/")
        with (
            patch("wagtail_soca.http.ssl.create_default_context", return_value=self.client_context),
            self.assertRaises(SocaError),
        ):
            request_json(self.origin.replace("provider.example.com", "other.example.com") + "/")
