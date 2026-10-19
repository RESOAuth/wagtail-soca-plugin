"""In-process OIDC provider fixture: real signatures and client assertion / PKCE checks."""

import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from wagtail_soca.config import get_config
from wagtail_soca.protocol import b64

ISSUER = "https://provider.example.com"


class Provider:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key()))
        self.public.update(kid="provider-key", alg="ES256", use="sig")
        self.document = {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks",
            "userinfo_endpoint": ISSUER + "/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "id_token_signing_alg_values_supported": ["ES256", "RS256"],
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }
        self.codes = {}
        self.last_form = None
        self.overrides = {}
        self.omit = set()
        self.headers = {"kid": "provider-key"}
        self.userinfo = {"sub": "person-123", "email": "editor@example.com", "email_verified": True}
        self.jwks = {"keys": [self.public]}

    def authorize(self, location):
        params = {name: values[0] for name, values in parse_qs(urlsplit(location).query).items()}
        assert params["response_type"] == "code"
        assert params["response_mode"] == "query"
        assert params["code_challenge_method"] == "S256"
        assert params["redirect_uri"] == get_config().url("callback")
        assert params["client_id"] == get_config().client_id
        code = secrets.token_urlsafe(32)
        self.codes[code] = params
        return {"state": params["state"], "code": code, "iss": ISSUER}

    def fetch(self, url, *, form=None, bearer=None):
        if url == ISSUER + "/.well-known/openid-configuration":
            return self.document
        if url == ISSUER + "/jwks":
            return self.jwks
        if url == ISSUER + "/userinfo":
            assert bearer == "fixture-access"
            return self.userinfo
        if url == ISSUER + "/token":
            self.last_form = form
            config = get_config()
            params = self.codes.pop(form["code"])
            assert form["grant_type"] == "authorization_code"
            assert (
                form["client_assertion_type"]
                == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            assert form["client_id"] == config.client_id
            assert form["redirect_uri"] == params["redirect_uri"]
            assert (
                b64(hashlib.sha256(form["code_verifier"].encode()).digest())
                == params["code_challenge"]
            )
            audience = ISSUER if config.assertion_audience == "issuer" else ISSUER + "/token"
            client_claims = jwt.decode(
                form["client_assertion"],
                config.private_key.public_key(),
                algorithms=["ES256"],
                issuer=config.client_id,
                audience=audience,
            )
            assert client_claims["sub"] == config.client_id
            assert client_claims["exp"] - client_claims["iat"] == 60
            assert len(client_claims["jti"]) >= 32
            now = int(time.time())
            claims = {
                "iss": ISSUER,
                "sub": "person-123",
                "aud": config.client_id,
                "iat": now,
                "exp": now + 300,
                "nonce": params["nonce"],
                "email": "editor@example.com",
                "email_verified": True,
                "at_hash": b64(hashlib.sha256(b"fixture-access").digest()[:16]),
                "c_hash": b64(hashlib.sha256(form["code"].encode()).digest()[:16]),
            }
            claims.update(self.overrides)
            for name in self.omit:
                claims.pop(name, None)
            return {
                "id_token": jwt.encode(
                    claims, self.key, algorithm=config.id_token_alg, headers=self.headers
                ),
                "access_token": "fixture-access",
                "token_type": "Bearer",
            }
        if url == get_config().client_id:
            return get_config().document()
        if url == get_config().url("jwks"):
            return {"keys": [get_config().public_key]}
        raise AssertionError("Unexpected fixture request")
