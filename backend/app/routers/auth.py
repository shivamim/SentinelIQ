"""Authentication router — Supabase Auth integration."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional

from app.auth import get_current_user, decode_supabase_token, require_role
from app.models import User
from app.schemas import UserOut, SupabaseLogin, Token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str = "analyst"


@router.post("/login", response_model=Token)
async def login(credentials: SupabaseLogin):
    """Login via Supabase Auth.

    The frontend calls Supabase signInWithPassword directly, then sends
    the Supabase JWT to this endpoint for verification. This endpoint
    validates the token and returns it (the real auth is Supabase-side).
    """
    # In Supabase Auth flow, the frontend gets the JWT directly from Supabase.
    # This endpoint exists for API documentation / token validation.
    # The actual auth happens via the `get_current_user` dependency.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Direct login is handled by Supabase Auth on the frontend. "
               "Send the Supabase JWT as a Bearer token in the Authorization header.",
    )


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return current_user


@router.post("/verify")
async def verify_token(current_user: User = Depends(get_current_user)):
    """Verify a Supabase JWT token and return user info."""
    return {
        "valid": True,
        "user_id": str(current_user.id),
        "email": current_user.email,
        "role": current_user.role,
    }
