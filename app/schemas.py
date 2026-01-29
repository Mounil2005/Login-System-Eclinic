"""
Pydantic Schemas
=================
Request and response schemas for API validation.

These schemas define the exact structure of API requests and responses,
providing automatic validation and documentation.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, field_validator
import re


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class SendOTPRequest(BaseModel):
    """
    Request schema for sending OTP.
    
    Example:
        {
            "mobile_number": "+91XXXXXXXXXX"
        }
    """
    mobile_number: str = Field(
        ...,
        description="Mobile number in E.164 format (e.g., +91XXXXXXXXXX)",
        examples=["+919876543210"]
    )
    
    @field_validator("mobile_number")
    @classmethod
    def validate_mobile_number(cls, value: str) -> str:
        """
        Validate mobile number format.
        
        Accepts E.164 format: +[country code][number]
        For India: +91XXXXXXXXXX (10 digits after country code)
        """
        # Remove any whitespace
        value = value.strip().replace(" ", "")
        
        # Basic E.164 format validation
        # Allows international numbers but focuses on Indian format
        pattern = r"^\+[1-9]\d{10,14}$"
        
        if not re.match(pattern, value):
            raise ValueError(
                "Invalid mobile number format. "
                "Use E.164 format: +91XXXXXXXXXX"
            )
        
        return value


class VerifyOTPRequest(BaseModel):
    """
    Request schema for verifying OTP.
    
    Example:
        {
            "mobile_number": "+91XXXXXXXXXX",
            "otp": "123456"
        }
    """
    mobile_number: str = Field(
        ...,
        description="Mobile number in E.164 format",
        examples=["+919876543210"]
    )
    otp: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-digit OTP received via SMS",
        examples=["123456"]
    )
    
    @field_validator("mobile_number")
    @classmethod
    def validate_mobile_number(cls, value: str) -> str:
        """Validate mobile number format (same as SendOTPRequest)."""
        value = value.strip().replace(" ", "")
        pattern = r"^\+[1-9]\d{10,14}$"
        
        if not re.match(pattern, value):
            raise ValueError(
                "Invalid mobile number format. "
                "Use E.164 format: +91XXXXXXXXXX"
            )
        
        return value
    
    @field_validator("otp")
    @classmethod
    def validate_otp(cls, value: str) -> str:
        """Validate OTP is 6 digits."""
        value = value.strip()
        
        if not value.isdigit():
            raise ValueError("OTP must contain only digits")
        
        if len(value) != 6:
            raise ValueError("OTP must be exactly 6 digits")
        
        return value


class CompleteProfileRequest(BaseModel):
    """Request schema for completing Google OAuth user profile."""
    mobile_number: str


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------

class SendOTPResponse(BaseModel):
    """
    Response schema for send OTP endpoint.
    
    Note: OTP is NEVER included in response for security.
    """
    success: bool = Field(
        ...,
        description="Whether OTP was sent successfully"
    )
    message: str = Field(
        ...,
        description="Human-readable status message"
    )
    expires_in_seconds: int = Field(
        ...,
        description="OTP validity period in seconds"
    )
    resend_available_in_seconds: Optional[int] = Field(
        default=None,
        description="Seconds until resend is available (if rate limited)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "OTP sent successfully",
                "expires_in_seconds": 300,
                "resend_available_in_seconds": None
            }
        }


class VerifyOTPResponse(BaseModel):
    """
    Response schema for verify OTP endpoint.
    
    Returns JWT token on successful verification.
    """
    success: bool = Field(
        ...,
        description="Whether verification was successful"
    )
    message: str = Field(
        ...,
        description="Human-readable status message"
    )
    token: Optional[str] = Field(
        default=None,
        description="JWT access token (only on success)"
    )
    role: Optional[str] = Field(
        default=None,
        description="User role (only on success)"
    )
    user_id: Optional[str] = Field(
        default=None,
        description="User ID (only on success)"
    )
    is_new_user: Optional[bool] = Field(
        default=None,
        description="Whether this is a newly created user"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "OTP verified successfully",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "role": "patient",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "is_new_user": False
            }
        }


class UserResponse(BaseModel):
    """
    Response schema for user information.
    
    Used by /me endpoint.
    """
    user_id: str = Field(
        ...,
        description="Unique user identifier (UUID)"
    )
    mobile_number: Optional[str] = Field(
        None,
        description="User's mobile number (if provided)"
    )
    email: Optional[str] = Field(
        None,
        description="User's email address"
    )
    full_name: Optional[str] = Field(
        None,
        description="User's full name"
    )
    profile_picture: Optional[str] = Field(
        None,
        description="URL to user's profile picture"
    )
    role: str = Field(
        ...,
        description="User's role in the system"
    )
    is_active: bool = Field(
        ...,
        description="Whether the user account is active"
    )
    is_mobile_verified: bool = Field(
        ...,
        description="Whether mobile number is verified"
    )
    is_profile_complete: bool = Field(
        ...,
        description="Whether user profile is complete"
    )
    created_at: datetime = Field(
        ...,
        description="Account creation timestamp"
    )
    last_login_at: Optional[datetime] = Field(
        default=None,
        description="Last login timestamp"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "mobile_number": "+919876543210",
                "role": "patient",
                "is_active": True,
                "created_at": "2025-01-20T10:30:00Z",
                "last_login_at": "2025-01-20T10:30:00Z"
            }
        }


# ---------------------------------------------------------------------------
# Google OAuth Schemas
# ---------------------------------------------------------------------------

class GoogleAuthURLResponse(BaseModel):
    """
    Response schema for Google OAuth authorization URL.
    """
    auth_url: str = Field(
        ...,
        description="Google OAuth authorization URL to redirect user to"
    )
    state: Optional[str] = Field(
        None,
        description="State parameter for CSRF protection"
    )


class GoogleCallbackResponse(BaseModel):
    """
    Response schema for Google OAuth callback handling.
    """
    success: bool
    message: str
    token: Optional[str] = Field(
        None,
        description="JWT token for existing users"
    )
    temp_token: Optional[str] = Field(
        None,
        description="Temporary token for profile completion"
    )
    user: Optional["UserResponse"] = Field(
        None,
        description="Complete user data for existing users"
    )
    user_info: Optional[dict] = Field(
        None,
        description="Google user info for new users"
    )
    requires_profile_completion: bool = Field(
        ...,
        description="Whether user needs to complete profile setup"
    )


class CompleteProfileResponse(BaseModel):
    """
    Response schema for profile completion.
    """
    success: bool
    message: str
    token: str = Field(
        ...,
        description="JWT authentication token"
    )
    user: "UserResponse" = Field(
        ...,
        description="Complete user profile"
    )
    is_new_user: bool = Field(
        ...,
        description="Whether this is a new user registration"
    )


class ErrorResponse(BaseModel):
    """
    Standard error response schema.
    """
    success: bool = Field(default=False)
    error: str = Field(
        ...,
        description="Error type/code"
    )
    message: str = Field(
        ...,
        description="Human-readable error message"
    )
    details: Optional[dict] = Field(
        default=None,
        description="Additional error details"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "error": "INVALID_OTP",
                "message": "The OTP entered is incorrect",
                "details": {"attempts_remaining": 2}
            }
        }


# ---------------------------------------------------------------------------
# Email OTP Schemas
# ---------------------------------------------------------------------------

class SendEmailOTPRequest(BaseModel):
    """Request schema for sending OTP to email address."""
    email: str = Field(
        ...,
        description="Email address to send OTP to",
        examples=["user@example.com"]
    )
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        """Validate email format."""
        value = value.strip().lower()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            raise ValueError("Invalid email format")
        
        return value


class VerifyEmailOTPRequest(BaseModel):
    """Request schema for verifying email OTP."""
    email: str = Field(
        ...,
        description="Email address that received the OTP",
        examples=["user@example.com"]
    )
    otp: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-digit OTP received via email",
        examples=["123456"]
    )
