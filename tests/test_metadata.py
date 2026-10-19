import base64
import json

from django.conf import settings
from django.test import TestCase, override_settings

from wagtail_soca.config import get_config
from wagtail_soca.errors import SocaError

PROXY = "https://dynamic-cimd.resoauth.cloud/cimd/%s"


class MetadataTests(TestCase):
    def test_default_issuer_is_resoauth(self):
        values = {name: value for name, value in settings.SOCA.items() if name != "ISSUER"}
        with override_settings(SOCA=values):
            self.assertEqual(get_config().issuer, "https://auth.resoauth.cloud")

    def test_proxy_encodes_only_metadata_and_public_key(self):
        with override_settings(SOCA={**settings.SOCA, "METADATA_PROXY": PROXY}):
            config = get_config()
            encoded = config.client_id.removeprefix(PROXY.replace("%s", ""))
            document = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            self.assertEqual(document, config.metadata())
            self.assertEqual(document["jwks"], {"keys": [config.public_key]})
            self.assertNotIn("jwks_uri", document)
            self.assertNotIn("client_id", document)
            self.assertNotIn("d", document["jwks"]["keys"][0])
            self.assertNotIn("ALLOW_EMAILS", document)
            self.assertEqual(config.document(), {"client_id": config.client_id, **document})
            self.assertEqual(config.client_id, get_config().client_id)

    def test_self_hosted_remains_the_package_default(self):
        config = get_config()
        self.assertEqual(config.client_id, "https://wagtail.example.com/soca/client.json")
        self.assertIn("jwks_uri", config.document())
        self.assertNotIn("jwks", config.document())

    def test_invalid_proxy_templates(self):
        for template in (
            "http://proxy.example.com/cimd/%s",
            "https://%s.example.com/cimd/",
            "https://proxy.example.com/cimd/?data=%s",
            "https://proxy.example.com/cimd/",
            "https://proxy.example.com/%s/%s",
            "https://proxy.example.com/../%s",
        ):
            with (
                self.subTest(template=template),
                override_settings(SOCA={**settings.SOCA, "METADATA_PROXY": template}),
                self.assertRaises(SocaError),
            ):
                get_config()
