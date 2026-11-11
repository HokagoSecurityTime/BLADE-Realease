import jwt
from pydantic import ValidationError
from common.schema import JWTClaims


class AuthenticationError(ValueError):
    pass


def authenticate(header: str | None, secret: str) -> JWTClaims | None:
    parts = header.split() if header else []
    if len(parts) != 2 or parts[0].lower() != 'bearer' or not secret:
        return None
    try:
        data = jwt.decode(parts[1], secret, algorithms=['HS256'],
                          options={'require': ['sub', 'exp', 'roles', 'tenant_id', 'membership']})
        return JWTClaims.model_validate(data)
    except (jwt.InvalidTokenError, ValidationError):
        return None
