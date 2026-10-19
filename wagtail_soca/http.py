"""Small HTTPS-only transport with DNS validation and connection address pinning."""

import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import unquote, urlencode, urlsplit

import urllib3

from .errors import SocaError

MAX_BODY = 256 * 1024


def unique_object(pairs):
    document = {}
    for name, value in pairs:
        if name in document:
            raise ValueError("Duplicate JSON member")
        document[name] = value
    return document


def reject_constant(value):
    raise ValueError("Non-finite JSON number")


def validate_url(url):
    if not isinstance(url, str) or len(url) > 8192 or not url.isascii():
        raise SocaError("invalid_url")
    if re.search(r"[\x00-\x20\x7f\\]", url):
        raise SocaError("invalid_url")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise SocaError("invalid_url") from exc
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "#" in url
        or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host)
        or "." not in host
        or any(p in (".", "..") for p in unquote(parsed.path).split("/"))
        or (port is not None and port < 1)
    ):
        raise SocaError("invalid_url")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SocaError("ip_literal")
    return parsed


def public_addresses(host, port):
    try:
        addresses = list(
            dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        )
    except OSError as exc:
        raise SocaError("dns_failed") from exc
    if not addresses or any(
        not ipaddress.ip_address(address).is_global
        or ipaddress.ip_address(address).is_multicast
        or getattr(ipaddress.ip_address(address), "ipv4_mapped", None) is not None
        for address in addresses
    ):
        raise SocaError("nonpublic_address")
    return addresses


def request_json(url, *, form=None, bearer=None):
    parsed = validate_url(url)
    port = parsed.port or 443
    address = public_addresses(parsed.hostname, port)[0]
    headers = {
        "Accept": "application/json",
        "Host": parsed.netloc,
        "User-Agent": "wagtail-soca/0.0.1",
        "Accept-Encoding": "identity",
    }
    body = None
    if form is not None:
        body = urlencode(form).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer is not None:
        if not isinstance(bearer, str) or not re.fullmatch(r"[A-Za-z0-9\-._~+/]+=*", bearer):
            raise SocaError("invalid_access_token")
        headers["Authorization"] = "Bearer " + bearer
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    # No environment proxies, DNS re-resolution, redirect following or implicit retries.
    pool = urllib3.HTTPSConnectionPool(
        address,
        port=port,
        server_hostname=parsed.hostname,
        assert_hostname=parsed.hostname,
        ssl_context=ssl.create_default_context(),
        timeout=urllib3.Timeout(connect=3, read=8),
        retries=False,
    )
    response = None
    try:
        response = pool.urlopen(
            "POST" if form is not None else "GET",
            path,
            body=body,
            headers=headers,
            redirect=False,
            preload_content=False,
        )
        media_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if response.status != 200 or media_type not in (
            "application/json",
            "application/jwk-set+json",
        ):
            raise SocaError("http_response")
        if response.headers.get("Content-Encoding", "identity") != "identity":
            raise SocaError("encoded_response")
        data = response.read(MAX_BODY + 1, decode_content=False)
        if len(data) > MAX_BODY:
            raise SocaError("response_too_large")
        document = json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(document, dict):
            raise SocaError("invalid_json_object")
        return document
    except (urllib3.exceptions.HTTPError, OSError, ValueError, RecursionError) as exc:
        raise SocaError("http_failed") from exc
    finally:
        if response is not None:
            response.close()
        pool.close()
