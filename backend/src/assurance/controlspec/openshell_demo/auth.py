"""Verify the pinned OpenShell extension JWT contract, never sandbox bootstrap JWTs."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class AuthenticationError(ValueError):
    """No authenticated authority could be established."""


@dataclass(frozen=True)
class ExtensionIdentity:
    gateway_id: str
    caller_kind: Literal["gateway", "supervisor"]
    sandbox_id: str | None


class ExtensionVerifier:
    """Operator-pinned Ed25519 keys; no request-controlled key URL or algorithm."""

    def __init__(self, gateway_id: str, audience: str, keys: Mapping[str, bytes]) -> None:
        if not gateway_id or not audience or not keys:
            raise ValueError("gateway, audience and verification keys are required")
        self.gateway_id = gateway_id
        self.issuer = f"openshell-gateway:{gateway_id}"
        self.audience = audience
        parsed: dict[str, Ed25519PublicKey] = {}
        for kid, pem in keys.items():
            key = load_pem_public_key(pem)
            if not kid or not isinstance(key, Ed25519PublicKey):
                raise ValueError("named Ed25519 verification key required")
            parsed[kid] = key
        self.keys = MappingProxyType(parsed)

    def verify(self, token: str) -> ExtensionIdentity:
        try:
            if len(token) > 16384:
                raise AuthenticationError("invalid extension identity")
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "EdDSA" or header.get("typ") != "openshell-ext+jwt":
                raise AuthenticationError("invalid extension identity")
            key = self.keys.get(header.get("kid", ""))
            if key is None:
                raise AuthenticationError("invalid extension identity")
            claims = jwt.decode(
                token, key, algorithms=["EdDSA"], issuer=self.issuer, audience=self.audience,
                options={"require": ["iss", "aud", "sub", "iat", "exp", "jti", "caller_kind"],
                         "strict_aud": True},
            )
            if (type(claims["iat"]) is not int or type(claims["exp"]) is not int
                    or not 0 < claims["exp"] - claims["iat"] <= 3600
                    or not isinstance(claims["jti"], str) or not claims["jti"]):
                raise AuthenticationError("invalid extension identity")
            kind = claims["caller_kind"]
            sandbox = claims.get("sandbox_id")
            if kind == "gateway":
                if sandbox is not None or claims["sub"] != self.issuer:
                    raise AuthenticationError("invalid extension identity")
                return ExtensionIdentity(self.gateway_id, "gateway", None)
            if (kind != "supervisor" or not isinstance(sandbox, str) or not sandbox.strip()
                    or len(sandbox) > 256 or claims["sub"] != f"spiffe://openshell/sandbox/{sandbox}"):
                raise AuthenticationError("invalid extension identity")
            return ExtensionIdentity(self.gateway_id, "supervisor", sandbox)
        except (jwt.PyJWTError, TypeError, KeyError) as exc:
            raise AuthenticationError("invalid extension identity") from exc
