"""
JWT Service
============
JSON Web Token generation and validation.

Tokens are used for stateless authentication across web and mobile clients.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from uuid import UUID

from jose import jwt, JWTError, ExpiredSignatureError

from app.config import settings
from app.models import User


class JWTService:
    """
    Service for JWT token operations.
    
    Handles:
    - Token generation with user claims
    - Token validation and decoding
    - Token refresh (if needed)
    """
    
    def __init__(self):
        """Initialize JWT service with configuration."""
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.expiry_minutes = settings.JWT_EXPIRY_MINUTES
    
    def create_access_token(
        self, 
        user: User,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a JWT access token for a user.
        
        Token payload includes:
        - sub: User ID (subject)
        - mobile: Mobile number
        - role: User role
        - exp: Expiration timestamp
        - iat: Issued at timestamp
        - type: Token type (access)
        
        Args:
            user: User model instance
            additional_claims: Optional extra claims to include
        
        Returns:
            str: Encoded JWT token
            
        Example:
            >>> token = jwt_service.create_access_token(user)
            >>> # Returns: "eyJhbGciOiJIUzI1NiIs..."
        """
        # Calculate expiration time
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=self.expiry_minutes)
        
        # Build token payload
        payload = {
            # Standard JWT claims
            "sub": str(user.id),              # Subject (user ID)
            "exp": expires_at,                 # Expiration time
            "iat": now,                        # Issued at
            "nbf": now,                        # Not before
            
            # Custom claims for E-Clinic
            "mobile": user.mobile_number,      # Mobile number
            "role": user.role.value,           # User role
            "type": "access",                  # Token type
        }
        
        # Add any additional claims
        if additional_claims:
            payload.update(additional_claims)
        
        # Encode and return token
        token = jwt.encode(
            payload, 
            self.secret_key, 
            algorithm=self.algorithm
        )
        
        return token
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate a JWT token.
        
        Validates:
        - Signature integrity
        - Expiration time
        - Token structure
        
        Args:
            token: JWT token string
        
        Returns:
            dict: Decoded payload if valid, None if invalid
            
        Raises:
            None - returns None on any error for security
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
            
        except ExpiredSignatureError:
            # Token has expired
            return None
            
        except JWTError:
            # Invalid token (bad signature, malformed, etc.)
            return None
    
    def get_user_id_from_token(self, token: str) -> Optional[str]:
        """
        Extract user ID from a valid token.
        
        Args:
            token: JWT token string
        
        Returns:
            str: User ID if token is valid, None otherwise
        """
        payload = self.decode_token(token)
        if payload:
            return payload.get("sub")
        return None
    
    def get_token_claims(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get all claims from a valid token.
        
        Args:
            token: JWT token string
        
        Returns:
            dict: All token claims if valid, None otherwise
        """
        return self.decode_token(token)
    
    def is_token_valid(self, token: str) -> bool:
        """
        Check if a token is valid.
        
        Args:
            token: JWT token string
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        return self.decode_token(token) is not None
    
    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token.
        
        Args:
            token: JWT token string
        
        Returns:
            datetime: Expiration time if token is valid, None otherwise
        """
        payload = self.decode_token(token)
        if payload and "exp" in payload:
            return datetime.fromtimestamp(payload["exp"])
        return None


# Create a singleton instance
jwt_service = JWTService()
