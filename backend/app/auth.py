"""Supabase Auth — verify JWTs issued by Supabase, NOT custom bcrypt+JWT."""
from typing import Optional, Literal
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.config import get_settings
from app.database import get_db
from app.models import User

settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def decode_supabase_token(token: str) -> dict:
    """Decode and verify a Supabase-issued JWT.

    Supabase JWTs are signed with the project's JWT secret.
    We verify the signature and expiration, then extract claims.
    """
    if not settings.SUPABASE_JWT_SECRET:
        raise RuntimeError("SUPABASE_JWT_SECRET is required for auth verification")
    try:
        payload = jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},  # Supabase uses its own aud
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Supabase token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: extract and verify Supabase JWT, look up local user."""
    payload = decode_supabase_token(token)

    # Supabase puts the user UUID in 'sub'
    supabase_uid: str = payload.get("sub")
    if supabase_uid is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing 'sub' claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Look up local user by supabase_uid
    result = await db.execute(select(User).where(User.supabase_uid == supabase_uid))
    user = result.scalar_one_or_none()

    if user is None:
        # Auto-provision: create local user record from Supabase claims
        email = payload.get("email", "")
        role = payload.get("app_metadata", {}).get("role", "analyst")
        # Validate role
        if role not in ("analyst", "senior_analyst", "admin"):
            role = "analyst"
        user = User(supabase_uid=supabase_uid, email=email, role=role)
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return user


def require_role(*roles: Literal["analyst", "senior_analyst", "admin"]):
    """Dependency factory: enforce RBAC role requirement."""
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {roles}, have: {current_user.role}",
            )
        return current_user
    return checker
