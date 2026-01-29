"""
FastAPI Dependencies
=====================
Reusable dependencies for authentication and authorization.

These dependencies are injected into route handlers to:
- Validate JWT tokens
- Get current user
- Check role-based access
"""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.services.jwt_service import jwt_service

# ---------------------------------------------------------------------------
# Security Scheme
# ---------------------------------------------------------------------------
# HTTPBearer extracts Bearer token from Authorization header
security = HTTPBearer(
    scheme_name="JWT",
    description="Enter your JWT token (without 'Bearer' prefix)",
    auto_error=True  # Raise 401 if no token provided
)

# Optional security for routes that work with or without auth
optional_security = HTTPBearer(
    scheme_name="JWT",
    auto_error=False  # Don't raise error if no token
)


# ---------------------------------------------------------------------------
# Get Current User
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user.
    
    Validates JWT token and returns the associated user.
    
    Args:
        credentials: Bearer token from Authorization header
        db: Database session
    
    Returns:
        User: Authenticated user object
    
    Raises:
        HTTPException 401: If token is invalid or expired
        HTTPException 401: If user not found
        HTTPException 403: If user account is inactive
        
    Usage:
        @app.get("/protected")
        async def protected_route(user: User = Depends(get_current_user)):
            return {"user_id": str(user.id)}
    """
    # Extract token
    token = credentials.credentials
    
    # Decode and validate token
    payload = jwt_service.decode_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Extract user ID from token
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Get user from database
    try:
        user = db.query(User).filter(
            User.id == UUID(user_id)
        ).first()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional dependency for routes that work with or without auth.
    
    Returns None if no token provided, user if valid token.
    
    Usage:
        @app.get("/items")
        async def get_items(user: Optional[User] = Depends(get_current_user_optional)):
            if user:
                return {"personalized": True}
            return {"personalized": False}
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


# ---------------------------------------------------------------------------
# Role-Based Access Control
# ---------------------------------------------------------------------------

def require_role(*allowed_roles: UserRole):
    """
    Dependency factory for role-based access control.
    
    Creates a dependency that checks if the current user
    has one of the allowed roles.
    
    Args:
        *allowed_roles: Roles that are allowed to access the route
    
    Returns:
        Dependency function that validates role
        
    Usage:
        @app.get("/admin-only")
        async def admin_route(
            user: User = Depends(require_role(UserRole.CLINIC_ADMIN))
        ):
            return {"admin": True}
        
        @app.get("/staff-only")
        async def staff_route(
            user: User = Depends(require_role(UserRole.DOCTOR, UserRole.LAB_ASSISTANT))
        ):
            return {"staff": True}
    """
    async def role_checker(
        user: User = Depends(get_current_user)
    ) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {', '.join(r.value for r in allowed_roles)}"
            )
        return user
    
    return role_checker


# ---------------------------------------------------------------------------
# Convenience Dependencies
# ---------------------------------------------------------------------------

# Pre-built role dependencies for common use cases

async def get_patient(
    user: User = Depends(require_role(UserRole.PATIENT))
) -> User:
    """Require patient role."""
    return user


async def get_doctor(
    user: User = Depends(require_role(UserRole.DOCTOR))
) -> User:
    """Require doctor role."""
    return user


async def get_clinic_admin(
    user: User = Depends(require_role(UserRole.CLINIC_ADMIN))
) -> User:
    """Require clinic admin role."""
    return user


async def get_lab_assistant(
    user: User = Depends(require_role(UserRole.LAB_ASSISTANT))
) -> User:
    """Require lab assistant role."""
    return user


async def get_healthcare_provider(
    user: User = Depends(require_role(UserRole.DOCTOR, UserRole.LAB_ASSISTANT))
) -> User:
    """Require doctor or lab assistant role."""
    return user


async def get_admin_or_doctor(
    user: User = Depends(require_role(UserRole.CLINIC_ADMIN, UserRole.DOCTOR))
) -> User:
    """Require clinic admin or doctor role."""
    return user
