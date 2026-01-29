"""
Database Models
================
SQLAlchemy ORM models for the authentication system.

Tables:
- users: Registered users with roles
- otp_records: OTP verification records (hashed)
- roles: Available user roles
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime, Integer, Boolean, 
    ForeignKey, Enum as SQLEnum, Text
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from app.database import Base


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    """
    Available user roles in the E-Clinic system.
    
    - patient: Default role for new users
    - doctor: Healthcare provider
    - clinic_admin: Clinic administrator
    - lab_assistant: Laboratory staff
    """
    PATIENT = "patient"
    DOCTOR = "doctor"
    CLINIC_ADMIN = "clinic_admin"
    LAB_ASSISTANT = "lab_assistant"


class OTPStatus(str, enum.Enum):
    """
    OTP record status.
    
    - pending: OTP sent, awaiting verification
    - verified: OTP successfully verified
    - expired: OTP has expired
    - exhausted: Maximum attempts exceeded
    """
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


# ---------------------------------------------------------------------------
# User Model
# ---------------------------------------------------------------------------

class User(Base):
    """
    User model for storing registered users.
    
    Users are created automatically upon first successful OTP verification.
    Mobile number is the primary identifier (no email/password).
    """
    __tablename__ = "users"
    
    # Primary key - UUID for security (non-guessable)
    id = Column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4,
        index=True
    )
    
    # Mobile number - unique identifier for authentication
    mobile_number = Column(
        String(15), 
        unique=True, 
        nullable=True,  # Now nullable for Google users
        index=True,
        comment="Mobile number in E.164 format (e.g., +91XXXXXXXXXX)"
    )
    
    # Google OAuth fields
    email = Column(
        String(320),  # Max email length per RFC 5321
        unique=True,
        nullable=True,
        index=True,
        comment="Email address from Google OAuth or manual entry"
    )
    
    google_id = Column(
        String(100),
        unique=True,
        nullable=True,
        index=True,
        comment="Google user ID for OAuth authentication"
    )
    
    profile_picture = Column(
        String(500),
        nullable=True,
        comment="URL to user's profile picture from Google"
    )
    
    full_name = Column(
        String(100),
        nullable=True,
        comment="Full name from Google or manual entry"
    )
    
    # User role for access control
    role = Column(
        SQLEnum(UserRole), 
        default=UserRole.PATIENT, 
        nullable=False,
        comment="User role for authorization"
    )
    
    # Account status
    is_active = Column(
        Boolean, 
        default=True, 
        nullable=False,
        comment="Whether user account is active"
    )
    
    # Verification status
    is_mobile_verified = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether mobile number is verified via OTP"
    )
    
    is_profile_complete = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether user has completed profile setup"
    )
    
    # Timestamps
    created_at = Column(
        DateTime, 
        default=datetime.utcnow, 
        nullable=False,
        comment="Account creation timestamp"
    )
    updated_at = Column(
        DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow,
        nullable=False,
        comment="Last update timestamp"
    )
    last_login_at = Column(
        DateTime, 
        nullable=True,
        comment="Last successful login timestamp"
    )
    
    # Relationships
    otp_records = relationship("OTPRecord", back_populates="user")
    
    def __repr__(self):
        return f"<User(id={self.id}, mobile={self.mobile_number}, role={self.role})>"


# ---------------------------------------------------------------------------
# OTP Record Model
# ---------------------------------------------------------------------------

class OTPRecord(Base):
    """
    OTP record for tracking verification attempts.
    
    Security features:
    - OTP is stored hashed (never plain text)
    - Expiry timestamp enforced
    - Attempt counter with maximum limit
    - Status tracking for audit
    """
    __tablename__ = "otp_records"
    
    # Primary key
    id = Column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4
    )
    
    # Mobile number (for lookup before user exists)
    mobile_number = Column(
        String(15), 
        nullable=False, 
        index=True,
        comment="Mobile number in E.164 format"
    )
    
    # Link to user (nullable - user may not exist yet)
    user_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("users.id"), 
        nullable=True,
        index=True
    )
    
    # Hashed OTP - NEVER store plain OTP
    otp_hash = Column(
        String(255), 
        nullable=False,
        comment="Bcrypt hash of the OTP"
    )
    
    # Expiry timestamp
    expires_at = Column(
        DateTime, 
        nullable=False,
        comment="OTP expiration timestamp"
    )
    
    # Verification attempts counter
    attempts = Column(
        Integer, 
        default=0, 
        nullable=False,
        comment="Number of verification attempts"
    )
    
    # Maximum allowed attempts
    max_attempts = Column(
        Integer, 
        default=3, 
        nullable=False,
        comment="Maximum verification attempts allowed"
    )
    
    # OTP status
    status = Column(
        SQLEnum(OTPStatus), 
        default=OTPStatus.PENDING, 
        nullable=False,
        comment="Current OTP status"
    )
    
    # Timestamps
    created_at = Column(
        DateTime, 
        default=datetime.utcnow, 
        nullable=False,
        comment="OTP creation timestamp"
    )
    verified_at = Column(
        DateTime, 
        nullable=True,
        comment="Successful verification timestamp"
    )
    
    # Audit fields
    ip_address = Column(
        String(45), 
        nullable=True,
        comment="IP address of requester (for audit)"
    )
    user_agent = Column(
        Text, 
        nullable=True,
        comment="User agent string (for audit)"
    )
    
    # Relationships
    user = relationship("User", back_populates="otp_records")
    
    def __repr__(self):
        return f"<OTPRecord(id={self.id}, mobile={self.mobile_number}, status={self.status})>"
    
    @property
    def is_expired(self) -> bool:
        """Check if OTP has expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_exhausted(self) -> bool:
        """Check if maximum attempts exceeded."""
        return self.attempts >= self.max_attempts
    
    @property
    def is_valid(self) -> bool:
        """Check if OTP is still valid for verification."""
        return (
            self.status == OTPStatus.PENDING 
            and not self.is_expired 
            and not self.is_exhausted
        )
