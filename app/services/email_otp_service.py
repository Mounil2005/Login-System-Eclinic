"""
Email OTP Service
=================
Service for Email OTP generation, storage, and verification.

Similar to OTP service but for email-based authentication.
Handles complete email OTP lifecycle.
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple
import logging
import re

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, OTPRecord, OTPStatus, UserRole
from app.utils.security import generate_otp, hash_otp, verify_otp_hash

# Configure logging
logger = logging.getLogger(__name__)


class EmailOTPService:
    """
    Service for Email OTP operations.
    
    Similar to mobile OTP but for email authentication.
    """
    
    def __init__(self, db: Session):
        """Initialize Email OTP service with database session."""
        self.db = db
        self.otp_expiry_minutes = settings.OTP_EXPIRY_MINUTES
        self.max_attempts = settings.OTP_MAX_ATTEMPTS
        self.resend_cooldown = settings.OTP_RESEND_COOLDOWN_SECONDS
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    async def send_otp(
        self,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, str, Optional[int], Optional[int]]:
        """
        Generate, store, and send OTP to email.
        
        Args:
            email: Recipient email address
            ip_address: Requester IP for audit logging
            user_agent: Requester user agent for audit logging
        
        Returns:
            Tuple of (success, message, expires_in, resend_available_in)
        """
        # Validate email format
        if not self.validate_email(email):
            return False, "Invalid email format", None, None
        
        # Check resend cooldown
        latest_otp = self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == email,  # Using mobile_number field for email too
            OTPRecord.status == OTPStatus.PENDING
        ).order_by(OTPRecord.created_at.desc()).first()
        
        if latest_otp:
            time_since_creation = datetime.utcnow() - latest_otp.created_at
            if time_since_creation.total_seconds() < self.resend_cooldown:
                resend_wait = int(self.resend_cooldown - time_since_creation.total_seconds())
                return False, "Please wait before requesting another OTP", None, resend_wait
        
        # Invalidate existing pending OTPs for this email
        self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == email,
            OTPRecord.status == OTPStatus.PENDING
        ).update({OTPRecord.status: OTPStatus.EXPIRED})
        self.db.commit()
        
        # Generate OTP - use demo OTP in demo mode
        if settings.USE_DEMO_EMAIL_OTP:
            otp = settings.DEMO_EMAIL_OTP
        else:
            otp = generate_otp(length=6)
        
        otp_hash = hash_otp(otp)
        
        # Calculate expiry
        expires_at = datetime.utcnow() + timedelta(minutes=self.otp_expiry_minutes)
        
        # Get user if exists
        user = self.db.query(User).filter(User.email == email).first()
        
        # Create OTP record (using mobile_number field to store email)
        otp_record = OTPRecord(
            mobile_number=email,  # Store email in this field
            user_id=user.id if user else None,
            otp_hash=otp_hash,
            expires_at=expires_at,
            max_attempts=self.max_attempts,
            status=OTPStatus.PENDING,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(otp_record)
        self.db.commit()
        
        # Log OTP in demo mode
        if settings.USE_DEMO_EMAIL_OTP:
            print(
                f"\n{'='*60}\n"
                f"📧 DEMO EMAIL OTP MODE ENABLED\n"
                f"📨 Email: {email}\n"
                f"🔢 Demo OTP: {otp}\n"
                f"{'='*60}"
            )
        else:
            # Real mode: would send actual email (not implemented yet)
            logger.info(f"Email OTP would be sent to: {email}")
        
        logger.info(f"Email OTP sent to {email}")
        
        return True, "OTP sent to email successfully", self.otp_expiry_minutes * 60, None
    
    def verify_otp(
        self,
        email: str,
        otp: str
    ) -> Tuple[bool, str, Optional[User], Optional[str], bool]:
        """
        Verify OTP sent to email.
        
        Args:
            email: User's email address
            otp: OTP entered by user
        
        Returns:
            Tuple of (success, message, user, token, is_new_user)
        """
        # Get latest pending OTP record for this email
        otp_record = self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == email,
            OTPRecord.status == OTPStatus.PENDING
        ).order_by(OTPRecord.created_at.desc()).first()
        
        if not otp_record:
            return False, "No pending OTP found. Please request a new OTP.", None, None, False
        
        # Check if OTP is expired
        if datetime.utcnow() > otp_record.expires_at:
            otp_record.status = OTPStatus.EXPIRED
            self.db.commit()
            return False, "OTP has expired. Please request a new OTP.", None, None, False
        
        # Check if attempts exhausted
        if otp_record.attempts >= otp_record.max_attempts:
            otp_record.status = OTPStatus.EXHAUSTED
            self.db.commit()
            return False, "Maximum attempts exceeded. Please request a new OTP.", None, None, False
        
        # Increment attempt counter
        otp_record.attempts += 1
        self.db.commit()
        
        # Verify OTP - in demo mode, just check against demo OTP directly
        otp_valid = False
        if settings.USE_DEMO_EMAIL_OTP:
            # Demo mode: accept the demo OTP
            otp_valid = (otp == settings.DEMO_EMAIL_OTP)
        else:
            # Production mode: verify against hash
            otp_valid = verify_otp_hash(otp, otp_record.otp_hash)
        
        if not otp_valid:
            attempts_remaining = otp_record.max_attempts - otp_record.attempts
            
            if attempts_remaining <= 0:
                otp_record.status = OTPStatus.EXHAUSTED
                self.db.commit()
                return False, "Maximum attempts exceeded. Please request a new OTP.", None, None, False
            
            return False, f"Incorrect OTP. {attempts_remaining} attempts remaining.", None, None, False
        
        # OTP verified successfully
        otp_record.status = OTPStatus.VERIFIED
        otp_record.verified_at = datetime.utcnow()
        self.db.commit()
        
        # Get or create user
        user = self.db.query(User).filter(User.email == email).first()
        is_new_user = False
        
        if not user:
            # Create new user
            user = User(
                email=email,
                role=UserRole.PATIENT,
                is_active=True,
                is_mobile_verified=True,  # Email verified
                is_profile_complete=False
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            is_new_user = True
            logger.info(f"New user created via email OTP: {email}")
        else:
            # Update existing user
            user.is_mobile_verified = True
            user.last_login_at = datetime.utcnow()
            self.db.commit()
            logger.info(f"User logged in via email OTP: {email}")
        
        return True, "Email OTP verified successfully", user, None, is_new_user
