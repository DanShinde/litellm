from typing import Annotated, Literal, TypeAlias

from pydantic import AliasChoices, ConfigDict, Field, SecretStr, field_validator

from litellm.types.llms.base_model import LiteLLMBaseModel
from litellm.types.mcp import MCPAuth, MCPTokenEndpointAuthMethod


class _AuthProfile(LiteLLMBaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")

    @field_validator("id")
    @classmethod
    def _reject_reserved_id(cls, value: str) -> str:
        if value.lower() == "default":
            raise ValueError("the default credential has no profile id")
        return value


class StaticAuthProfile(_AuthProfile):
    auth_type: Literal[MCPAuth.api_key, MCPAuth.bearer_token, MCPAuth.basic, MCPAuth.token, MCPAuth.authorization]
    authentication_token: SecretStr | None = Field(
        default=None, exclude=True, repr=False, validation_alias=AliasChoices("authentication_token", "auth_value")
    )


class ClientCredentialsAuthProfile(_AuthProfile):
    auth_type: Literal[MCPAuth.oauth2]
    oauth2_flow: Literal["client_credentials"]
    token_url: str | None = None
    scopes: tuple[str, ...] | None = None
    token_endpoint_auth_method: MCPTokenEndpointAuthMethod | None = None
    client_id: SecretStr | None = Field(default=None, exclude=True, repr=False)
    client_secret: SecretStr | None = Field(default=None, exclude=True, repr=False)


MCPAuthProfile: TypeAlias = Annotated[
    StaticAuthProfile | ClientCredentialsAuthProfile, Field(discriminator="auth_type")
]
