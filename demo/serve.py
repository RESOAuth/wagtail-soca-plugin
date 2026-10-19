import ipaddress
import logging
import os
import secrets
import signal
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DATA_DIR = Path("/data")


def write_secret(path, value):
    if not path.exists():
        # Exclusive creation keeps existing credentials and keys stable across restarts.
        with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
            stream.write(value)


def prepare():
    DATA_DIR.mkdir(exist_ok=True)
    write_secret(DATA_DIR / "django-secret", secrets.token_urlsafe(64))
    write_secret(DATA_DIR / "admin-password", secrets.token_urlsafe(18))
    for name in ("soca.pem", "tls.key"):
        key = ec.generate_private_key(ec.SECP256R1())
        write_secret(
            DATA_DIR / name,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        )
    certificate_file = DATA_DIR / "tls.pem"
    if not certificate_file.exists():
        key = serialization.load_pem_private_key((DATA_DIR / "tls.key").read_bytes(), password=None)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wagtail.localhost")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("wagtail.localhost"),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


class ThreadedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class RequestLog(WSGIRequestHandler):
    def get_environ(self):
        environ = super().get_environ()
        environ["HTTPS"] = "on"
        return environ

    def log_request(self, code="-", size="-"):
        # OAuth state/codes/nonce must never appear in access logs.
        method = self.command.replace("\r", "\\r").replace("\n", "\\n")
        path = urlsplit(self.path).path.replace("\r", "\\r").replace("\n", "\\n")
        logging.getLogger("soca_demo.http").info("%s %s %s", method, path, code)


def main():
    prepare()
    os.environ["DJANGO_SETTINGS_MODULE"] = "demo.settings"
    import django

    django.setup()
    from django.contrib.auth import get_user_model
    from django.contrib.staticfiles.handlers import StaticFilesHandler
    from django.core.management import call_command
    from django.core.wsgi import get_wsgi_application

    call_command("check")
    call_command("migrate", interactive=False, verbosity=0)
    call_command("soca_cleanup", verbosity=0)
    users = get_user_model()
    if not users.objects.filter(username="admin").exists():
        users.objects.create_superuser(
            username="admin",
            email="",
            password=(DATA_DIR / "admin-password").read_text(),
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(DATA_DIR / "tls.pem", DATA_DIR / "tls.key")

    def stop(signum, frame):
        logging.getLogger("soca_demo").info("Stopping local demo")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    with make_server(
        "0.0.0.0",  # noqa: S104 - container port is published on host loopback only
        8443,
        StaticFilesHandler(get_wsgi_application()),
        server_class=ThreadedServer,
        handler_class=RequestLog,
    ) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        logging.getLogger("soca_demo").info(
            "Wagtail ready at https://wagtail.localhost:8443/admin/ (issuer: https://auth.resoauth.cloud)"
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
