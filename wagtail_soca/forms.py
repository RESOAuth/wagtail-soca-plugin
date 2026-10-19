import re

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from .config import get_config, get_values
from .errors import SocaError
from .provisioning import eligible_groups, provisioning_fields

DYNAMIC_CIMD = "https://dynamic-cimd.resoauth.cloud/cimd/%s"


class AdmissionListField(forms.CharField):
    def __init__(self, *, emails, **kwargs):
        self.emails = emails
        super().__init__(
            required=False, max_length=32000, widget=forms.Textarea(attrs={"rows": 4}), **kwargs
        )

    def clean(self, value):
        text = super().clean(value)
        entries = list(dict.fromkeys(x.lower() for x in re.split(r"[\s,;]+", text) if x))
        for entry in entries:
            try:
                validate_email(entry if self.emails else "policy@" + entry)
                if not entry.isascii() or "*" in entry:
                    raise ValidationError("invalid")
            except ValidationError as exc:
                kind = "email addresses" if self.emails else "domains"
                raise ValidationError(
                    f"Enter exact ASCII {kind}, one per line or separated by commas. Wildcards are not supported."
                ) from exc
        return entries


class SocaSettingsForm(forms.Form):
    revision = forms.UUIDField(required=False, widget=forms.HiddenInput)
    enabled = forms.BooleanField(
        required=False,
        label="Enable SSO",
        help_text="Show Continue with SSO on the login screen. Local password login remains available.",
    )
    issuer = forms.CharField(
        label="Provider issuer",
        max_length=2000,
        help_text="The exact HTTPS OpenID Connect issuer. RESOAuth: https://auth.resoauth.cloud",
    )
    metadata_mode = forms.ChoiceField(
        label="Client metadata",
        choices=[
            ("self", "Self-hosted — public HTTPS site"),
            ("proxy", "Dynamic CIMD — local development or metadata proxy"),
        ],
    )
    metadata_proxy = forms.CharField(
        required=False,
        label="Metadata proxy URL",
        max_length=2000,
        help_text="Use one literal %s in the path. Only public metadata and the public signing key are published.",
    )
    id_token_alg = forms.ChoiceField(
        label="ID token algorithm",
        choices=[("ES256", "ES256 (RESOAuth default)"), ("RS256", "RS256")],
    )
    assertion_audience = forms.ChoiceField(
        label="Client assertion audience",
        choices=[
            ("issuer", "Provider issuer (RESOAuth default)"),
            ("token_endpoint", "Token endpoint"),
        ],
    )
    allow_emails = AdmissionListField(
        emails=True,
        label="Allowed email addresses",
        help_text="Only verified provider emails passing these rules can sign in. Existing accounts must have Wagtail admin access.",
    )
    allow_domains = AdmissionListField(
        emails=False,
        label="Allowed domains",
        help_text="Exact domains only, without @. Subdomains are separate. Empty allow lists deny all SSO access.",
    )
    deny_emails = AdmissionListField(
        emails=True,
        label="Denied email addresses",
        help_text="Deny rules take priority over allow rules.",
    )
    deny_domains = AdmissionListField(
        emails=False, label="Denied domains", help_text="Exact domains only, without @."
    )
    create_users = forms.BooleanField(
        required=False,
        label="Create accounts on first SSO login",
        help_text="Off by default. Create an account only for a verified email admitted by the rules above. Existing usernames and permissions are never changed; blank names can be filled from verified profile claims.",
    )
    new_user_group = forms.ModelChoiceField(
        queryset=eligible_groups(),
        required=False,
        label="New account group",
        empty_label="Choose a group",
        help_text="Required when creating accounts. Only groups with Wagtail admin access are listed. New users receive this group's permissions, an unusable local password, and no staff or superuser flags.",
    )

    def __init__(self, *args, values, revision=None, **kwargs):
        initial = {
            "revision": revision,
            "enabled": values.get("ENABLED", False),
            "issuer": values.get("ISSUER", "https://auth.resoauth.cloud"),
            "metadata_mode": "proxy" if values.get("METADATA_PROXY") else "self",
            "metadata_proxy": values.get("METADATA_PROXY") or DYNAMIC_CIMD,
            "id_token_alg": values.get("ID_TOKEN_ALG", "ES256"),
            "assertion_audience": values.get("ASSERTION_AUDIENCE", "issuer"),
            "create_users": values.get("CREATE_USERS", False),
            "new_user_group": values.get("NEW_USER_GROUP"),
        }
        for name in ("allow_emails", "allow_domains", "deny_emails", "deny_domains"):
            initial[name] = "\n".join(values.get(name.upper(), []))
        super().__init__(*args, initial=initial, **kwargs)

    def to_settings(self):
        data = self.cleaned_data
        return {
            "ENABLED": data["enabled"],
            "ISSUER": data["issuer"],
            "METADATA_PROXY": data["metadata_proxy"] if data["metadata_mode"] == "proxy" else None,
            "ID_TOKEN_ALG": data["id_token_alg"],
            "ASSERTION_AUDIENCE": data["assertion_audience"],
            "CREATE_USERS": data["create_users"],
            "NEW_USER_GROUP": data["new_user_group"].pk if data["new_user_group"] else None,
            **{
                name.upper(): data[name]
                for name in ("allow_emails", "allow_domains", "deny_emails", "deny_domains")
            },
        }

    def clean(self):
        data = super().clean()
        if self.errors:
            return data
        if data["create_users"]:
            if not data["new_user_group"]:
                self.add_error("new_user_group", "Choose a group for new accounts.")
                return data
            try:
                provisioning_fields("soca-check@example.com")
            except SocaError as exc:
                raise ValidationError(
                    "This custom user model does not support automatic account creation."
                ) from exc
        if data["metadata_mode"] == "proxy" and not data["metadata_proxy"]:
            self.add_error("metadata_proxy", "Enter a metadata proxy URL.")
            return data
        try:
            get_config(
                values={**get_values(use_database=False), **self.to_settings()},
                require_enabled=False,
            )
        except SocaError as exc:
            raise ValidationError(
                f"Configuration could not be validated ({exc}). Check the HTTPS URLs, proxy template and deployment signing key."
            ) from exc
        return data
