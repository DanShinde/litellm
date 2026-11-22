from collections.abc import Callable, Mapping
from typing import Annotated, Final, Literal, TypeAlias

from pydantic import (
    AliasChoices,
    ConfigDict,
    Field,
    SecretStr,
    SerializerFunctionWrapHandler,
    TypeAdapter,
    ValidationError,
    WrapValidator,
    field_validator,
    model_serializer,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from litellm.types.llms.base_model import LiteLLMBaseModel
from litellm.types.mcp import MCPAuth, MCPTokenEndpointAuthMethod

_FIELDS: Final = TypeAdapter(Mapping[str, object])


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

    @model_serializer(mode="wrap")
    def _omit_absent_settings(self, handler: SerializerFunctionWrapHandler):  # noqa: ANN202  # Preserve the model's serialization schema
        return {key: value for key, value in _FIELDS.validate_python(handler(self)).items() if value is not None}


def _validate_profile(
    value: object, handler: Callable[[object], StaticAuthProfile | ClientCredentialsAuthProfile]
) -> StaticAuthProfile | ClientCredentialsAuthProfile:
    try:
        return handler(value)
    except ValidationError as exc:
        # Union errors can contain the entire credential-bearing request, including on a missing discriminator.
        errors: Final = [
            InitErrorDetails(
                type=PydanticCustomError(
                    "invalid_auth_profile",
                    "{reason}",
                    {"reason": "Unknown auth type" if error["type"] == "union_tag_invalid" else error["msg"]},
                ),
                loc=error["loc"],
                input=None,
            )
            for error in exc.errors(include_input=False)
        ]
        raise ValidationError.from_exception_data("MCPAuthProfile", errors) from None


MCPAuthProfile: TypeAlias = Annotated[
    StaticAuthProfile | ClientCredentialsAuthProfile, Field(discriminator="auth_type"), WrapValidator(_validate_profile)
]
