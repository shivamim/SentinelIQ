"""Supabase Auth — verify JWTs issued by Supabase."""

from typing import Literal
import json
import urllib.request

from jose import JWTError, jwt, jwk
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import get_settings
from app.database import get_db
from app.models import User


settings = get_settings()

# Supabase authentication is handled on the frontend.
# The backend receives the resulting Supabase access token
# through: Authorization: Bearer <token>
bearer_scheme = HTTPBearer(auto_error=True)


def _get_supabase_jwks() -> dict:
    """Fetch Supabase's public JWKS keys."""

    if not settings.SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is required for auth verification")

    jwks_url = (
        f"{settings.SUPABASE_URL.rstrip('/')}"
        "/auth/v1/.well-known/jwks.json"
    )

    try:
        with urllib.request.urlopen(jwks_url, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    except Exception as exc:
        raise RuntimeError(
            f"Unable to fetch Supabase JWKS: {exc}"
        ) from exc


def decode_supabase_token(token: str) -> dict:
    """
    Verify a Supabase JWT.

    Supports:
    - ES256: current asymmetric Supabase signing keys via JWKS
    - HS256: legacy Supabase JWT secret
    """

    try:
        # Read the JWT header without trusting it yet.
        header = jwt.get_unverified_header(token)

        kid = header.get("kid")
        algorithm = header.get("alg")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing 'kid' claim",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Only explicitly supported algorithms are accepted.
        if algorithm not in ("ES256", "HS256"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported JWT algorithm: {algorithm}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # ---------------------------------------------------------
        # Current Supabase authentication: ES256 + JWKS
        # ---------------------------------------------------------
        if algorithm == "ES256":
            jwks = _get_supabase_jwks()

            key_data = next(
                (
                    key
                    for key in jwks.get("keys", [])
                    if key.get("kid") == kid
                ),
                None,
            )

            if not key_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Supabase signing key not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            public_key = jwk.construct(
                key_data,
                algorithm="ES256",
            )

            issuer = (
                f"{settings.SUPABASE_URL.rstrip('/')}"
                "/auth/v1"
            )

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["ES256"],
                issuer=issuer,
                audience="authenticated",
            )

            return payload

        # ---------------------------------------------------------
        # Legacy Supabase authentication: HS256
        # ---------------------------------------------------------
        if not settings.SUPABASE_JWT_SECRET:
            raise RuntimeError(
                "SUPABASE_JWT_SECRET is required "
                "for HS256 auth verification"
            )

        payload = jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={
                "verify_aud": False,
            },
        )

        return payload

    except HTTPException:
        raise

    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Supabase token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to verify Supabase token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and verify Supabase JWT,
    then look up or create the local user.
    """

    # HTTPBearer has already extracted the token from:
    # Authorization: Bearer <token>
    token = credentials.credentials

    payload = decode_supabase_token(token)

    # Supabase user UUID
    supabase_uid = payload.get("sub")

    if not supabase_uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---------------------------------------------------------
    # Look up local user
    # ---------------------------------------------------------
    result = await db.execute(
        select(User).where(
            User.supabase_uid == supabase_uid
        )
    )

    user = result.scalar_one_or_none()

    # ---------------------------------------------------------
    # Automatically create local user if necessary
    # ---------------------------------------------------------
    if user is None:
        email = payload.get("email", "")

        app_metadata = payload.get(
            "app_metadata",
            {},
        )

        role = app_metadata.get(
            "role",
            "analyst",
        )

        if role not in (
            "analyst",
            "senior_analyst",
            "admin",
        ):
            role = "analyst"

        user = User(
            supabase_uid=supabase_uid,
            email=email,
            role=role,
        )

        db.add(user)

        await db.commit()
        await db.refresh(user)

    return user


def require_role(
    *roles: Literal[
        "analyst",
        "senior_analyst",
        "admin",
    ]
):
    """Dependency factory for role-based access control."""

    def checker(
        current_user: User = Depends(get_current_user),
    ) -> User:

        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. "
                    f"Required: {roles}, "
                    f"have: {current_user.role}"
                ),
            )

        return current_user

    return checker
