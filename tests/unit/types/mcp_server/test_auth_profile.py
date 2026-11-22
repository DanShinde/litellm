import json
from typing import Final

import pytest
from pydantic import TypeAdapter, ValidationError

from litellm.types.mcp_server.auth_profile import ClientCredentialsAuthProfile, MCPAuthProfile, StaticAuthProfile

PROFILES: Final = TypeAdapter(MCPAuthProfile)


@pytest.mark.parametrize("auth_type", ("api_key", "bearer_token", "basic", "token", "authorization"))
@pytest.mark.parametrize("field", ("authentication_token", "auth_value"))
def test_static_profile_accepts_the_token_but_only_serializes_public_fields(auth_type: str, field: str) -> None:
    profile: Final = PROFILES.validate_python({"id": "bot", "auth_type": auth_type, field: "test-token"})

    assert isinstance(profile, StaticAuthProfile)
    assert profile.authentication_token is not None and profile.authentication_token.get_secret_value() == "test-token"
    assert json.loads(profile.model_dump_json()) == {"id": "bot", "auth_type": auth_type}


@pytest.mark.parametrize("profile_id", ("", "a" * 65, "Default", "de fault", "bot\n"))
def test_profile_rejects_reserved_and_invalid_ids(profile_id: str) -> None:
    with pytest.raises(ValidationError):
        PROFILES.validate_python({"id": profile_id, "auth_type": "basic"})


def test_client_credentials_profile_returns_the_flow_settings_without_the_credentials() -> None:
    public: Final = {
        "id": "bot",
        "auth_type": "oauth2",
        "oauth2_flow": "client_credentials",
        "token_url": "https://issuer.example/token",
        "scopes": ["read"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    profile: Final = PROFILES.validate_python({**public, "client_id": "app-id", "client_secret": "app-secret"})

    assert isinstance(profile, ClientCredentialsAuthProfile)
    assert profile.client_id is not None and profile.client_id.get_secret_value() == "app-id"
    assert profile.client_secret is not None and profile.client_secret.get_secret_value() == "app-secret"
    assert PROFILES.dump_python(profile, mode="json") == public
    assert PROFILES.validate_python(public).model_dump(mode="json") == public


def test_resending_a_public_profile_preserves_omitted_oauth_settings() -> None:
    public: Final = {"id": "a" * 64, "auth_type": "oauth2", "oauth2_flow": "client_credentials"}
    profile: Final = PROFILES.validate_python({**public, "client_secret": "app-secret"})
    encoded: Final = PROFILES.dump_json(profile)

    assert json.loads(encoded) == public
    assert PROFILES.validate_json(encoded).model_fields_set == set(public)


@pytest.mark.parametrize(
    "settings",
    (
        {"auth_type": "oauth2"},
        {"auth_type": "oauth2", "oauth2_flow": "authorization_code"},
        {"auth_type": "basic", "oauth2_flow": "client_credentials"},
    ),
)
def test_profile_rejects_an_incompatible_flow(settings: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        PROFILES.validate_python({"id": "bot", **settings})
