"""
PDRI API Authentication
========================

JWT-based authentication and authorization middleware.

Usage:
    from pdri.api.auth import get_current_user, require_role

    @router.get("/protected")
    async def protected(user: CurrentUser = Depends(get_current_user)):
        return {"user_id": user.user_id}

    @router.delete("/admin-only")
    async def admin_only(user: CurrentUser = Depends(require_role("admin"))):
        return {"msg": "admin action"}

Author: PDRI Team
Version: 1.0.0
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# JWT secret — loaded from environment, with a dev-only default
JWT_SECRET = os.environ.get("JWT_SECRET", "pdri-dev-secret-CHANGE-IN-PRODUCTION")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))


# =============================================================================
# Models
# =============================================================================


class UserRole(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"       # Full access (compliance, config, all mutations)
    ANALYST = "analyst"   # Read + score + simulate + predict
    VIEWER = "viewer"     # Read-only access to nodes & dashboards


@dataclass
class CurrentUser:
    """Authenticated user context from a validated JWT."""
    user_id: str
    role: UserRole
    permissions: List[str]
    email: Optional[str] = None


# Role → permitted actions mapping
ROLE_PERMISSIONS: Dict[UserRole, List[str]] = {
    UserRole.ADMIN: [
        "read", "write", "delete", "score", "simulate",
        "predict", "compliance", "configure", "audit",
    ],
    UserRole.ANALYST: [
        "read", "score", "simulate", "predict",
    ],
    UserRole.VIEWER: [
        "read",
    ],
}


# =============================================================================
# Token Utilities
# =============================================================================


def _get_jwt_lib():
    """Import jwt library (jose or PyJWT)."""
    try:
        from jose import jwt, JWTError  # python-jose
        return jwt, JWTError
    except ImportError:
        pass

    try:
        import jwt as pyjwt  # PyJWT
        return pyjwt, pyjwt.PyJWTError
    except ImportError:
        raise ImportError(
            "JWT support requires 'python-jose' or 'PyJWT'. "
            "Install: pip install python-jose[cryptography]"
        )


def create_access_token(
    user_id: str,
    role: str = "viewer",
    email: Optional[str] = None,
    expires_minutes: int = JWT_EXPIRE_MINUTES,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id: Unique user identifier
        role: User role (admin, analyst, viewer)
        email: Optional email
        expires_minutes: Token TTL in minutes

    Returns:
        Encoded JWT string
    """
    jwt, _ = _get_jwt_lib()

    payload = {
        "sub": user_id,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
    }
    if email:
        payload["email"] = email

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.

    Args:
        token: Encoded JWT

    Returns:
        Decoded payload dict

    Raises:
        HTTPException 401 if token is invalid or expired
    """
    jwt, JWTError = _get_jwt_lib()

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if "sub" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# =============================================================================
# FastAPI Dependencies
# =============================================================================

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> CurrentUser:
    """
    FastAPI dependency that extracts and validates the current user from JWT.

    Usage:
        @router.get("/me")
        async def me(user: CurrentUser = Depends(get_current_user)):
            ...
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)

    role_str = payload.get("role", "viewer")
    try:
        role = UserRole(role_str)
    except ValueError:
        role = UserRole.VIEWER

    return CurrentUser(
        user_id=payload["sub"],
        role=role,
        permissions=ROLE_PERMISSIONS.get(role, []),
        email=payload.get("email"),
    )


def require_role(*allowed_roles: str):
    """
    FastAPI dependency factory for role-based access control.

    Args:
        allowed_roles: One or more role strings that are permitted

    Returns:
        FastAPI dependency that validates the user's role

    Usage:
        @router.delete("/admin")
        async def admin(user = Depends(require_role("admin"))):
            ...

        @router.post("/score")
        async def score(user = Depends(require_role("admin", "analyst"))):
            ...
    """
    allowed = {UserRole(r) for r in allowed_roles}

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not authorized. "
                       f"Required: {', '.join(r.value for r in allowed)}",
            )
        return user

    return _check
