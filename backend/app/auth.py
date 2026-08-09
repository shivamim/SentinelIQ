"""Supabase Auth — verify JWTs issued by Supabase."""

from typing import Literal
import json
import urllib.request
from functools import lru_cache

from jose import JWTError, jwt, jwk
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import get_settings
from app.database import get_db
from app.models import User


settings = get_settings()

# Use HTTPBearer for OpenAPI schema (not OAuth2PasswordBearer)
# This correctly represents that we expect a Bearer token from Supabase Auth
bearer_scheme = HTTPBearer(auto_error=True)

# JWKS cache to avoid fetching on every request
_jwks_cache: dict = {}


def _get_supabase_jwks() -> dict:
    """Fetch Supabase's public JWKS keys with caching."""

    if not settings.SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is required for auth verification")

    jwks_url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"

    # Check cache first (simple in-memory cache)
    if jwks_url in _jwks_cache:
        return _jwks_cache[jwks_url]

    try:
        with urllib.request.urlopen(jwks_url, timeout=10) as response:
            jwks = json.loads(response.read().decode("utf-8"))
            _jwks_cache[jwks_url] = jwks  # Cache indefinitely (key rotation is rare)
            return jwks
    except Exception as exc:
        raise RuntimeError(
            f"Unable to fetch Supabase JWKS: {exc}"
        ) from exc


def decode_supabase_token(token: str) -> dict:
    """Verify a Supabase JWT, including current ES256 tokens."""

    try:
        # Read token header without trusting it yet.
        header = jwt.get_unverified_header(token)

        kid = header.get("kid")
        algorithm = header.get("alg")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing 'kid' claim",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Only allow algorithms we explicitly support.
        if algorithm not in ("ES256", "HS256"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported JWT algorithm: {algorithm}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Current Supabase projects commonly use asymmetric ES256 signing.
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

            public_key = jwk.construct(key_data, algorithm="ES256")

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["ES256"],
                issuer=f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1",
                audience="authenticated",
            )

            return payload

        # Legacy HS256 support.
        if not settings.SUPABASE_JWT_SECRET:
            raise RuntimeError(
                "SUPABASE_JWT_SECRET is required for HS256 auth verification"
            )

        payload = jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )

        return payload

    except HTTPException:
        raise

    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Supabase token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to verify Supabase token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and verify Supabase JWT, then look up local user.
    
    The token is extracted from the Authorization: Bearer header.
    Supports both ES256 (asymmetric, current) and HS256 (legacy) tokens.
    """
    token = credentials.credentials
    payload = decode_supabase_token(token)

    # Supabase user UUID
    supabase_uid: str = payload.get("sub")

    if supabase_uid is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Look up local user.
    result = await db.execute(
        select(User).where(User.supabase_uid == supabase_uid)
    )

    user = result.scalar_one_or_none()

    # Automatically create local user if necessary.
    if user is None:
        email = payload.get("email", "")

        role = payload.get("app_metadata", {}).get(
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
    *roles: Literal["analyst", "senior_analyst", "admin"]
):
    """Dependency factory for RBAC."""

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
