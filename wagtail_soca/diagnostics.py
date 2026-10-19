from . import http, protocol
from .errors import SocaError


def check_connection(config):
    discovery = protocol.discover(config)
    if http.request_json(config.client_id) != config.document():
        raise SocaError("published_metadata_mismatch")
    if not config.metadata_proxy and http.request_json(config.url("jwks")) != {
        "keys": [config.public_key]
    }:
        raise SocaError("published_keys_mismatch")
    return discovery
