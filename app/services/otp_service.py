"""
OTP Service
============
Business logic for OTP generation, storage, and verification.

This service handles the complete OTP lifecycle:
1. Generate and store OTP (hashed)
2. Send via MSG91
3. Verify OTP and manage attempts
4. Create/update user on success
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import UUID
import logging

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, OTPRecord, OTPStatus, UserRole
from app.utils.security import generate_otp, hash_otp, verify_otp_hash
from app.services.msg91_service import msg91_service
from app.services.jwt_service import jwt_service

# Configure logging
logger = logging.getLogger(__name__)


class OTPService:
    """
    Service for OTP operations.
    
    Handles:
    - OTP generation and secure storage
    - Rate limiting (resend cooldown)
    - Verification with attempt tracking
    - User creation on first verification
    """
    
    def __init__(self, db: Session):
        """
        Initialize OTP service with database session.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
        self.otp_expiry_minutes = settings.OTP_EXPIRY_MINUTES
        self.max_attempts = settings.OTP_MAX_ATTEMPTS
        self.resend_cooldown = settings.OTP_RESEND_COOLDOWN_SECONDS
    
    # -------------------------------------------------------------------------
    # Send OTP
    # -------------------------------------------------------------------------
    
    async def send_otp(
        self, 
        mobile_number: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, str, Optional[int], Optional[int]]:
        """
        Generate, store, and send OTP to mobile number.
        
        Process:
        1. Check for resend cooldown
        2. Invalidate any existing pending OTPs
        3. Generate new OTP
        4. Store hashed OTP in database
        5. Send OTP via MSG91
        
        Args:
            mobile_number: Recipient mobile number (E.164 format)
            ip_address: Requester IP for audit logging
            user_agent: Requester user agent for audit logging
        
        Returns:
            Tuple of:
            - success (bool): Whether OTP was sent
            - message (str): Status message
            - expires_in (int or None): Seconds until OTP expires
            - resend_available_in (int or None): Seconds until resend allowed
        """
        # Check resend cooldown
        cooldown_remaining = self._check_resend_cooldown(mobile_number)
        if cooldown_remaining > 0:
            return (
                False,
                "Please wait before requesting another OTP",
                None,
                cooldown_remaining
            )
        
        # Invalidate existing pending OTPs for this number
        self._invalidate_pending_otps(mobile_number)
        
        # Generate new OTP (or use demo OTP)
        if settings.USE_DEMO_OTP:
            otp = settings.DEMO_OTP
            logger.warning(
                f"\n{'='*60}\n"
                f"🔓 DEMO OTP MODE ENABLED\n"
                f"📱 Mobile: {mobile_number}\n"
                f"🔢 Demo OTP: {otp}\n"
                f"{'='*60}"
            )
        else:
            otp = generate_otp(length=6)
        
        otp_hash = hash_otp(otp)
        
        # Calculate expiry
        expires_at = datetime.utcnow() + timedelta(
            minutes=self.otp_expiry_minutes
        )
        
        # Get user if exists (for linking OTP record)
        user = self._get_user_by_mobile(mobile_number)
        
        # Create OTP record
        otp_record = OTPRecord(
            mobile_number=mobile_number,
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
        
        # Send OTP via MSG91 (or skip if using demo OTP)
        if settings.USE_DEMO_OTP:
            # Skip MSG91 in demo mode
            logger.info(f"Demo OTP ready for {mobile_number}: {otp}")
            send_result = {"success": True, "message": "Demo OTP mode"}
        else:
            send_result = await msg91_service.send_otp(mobile_number, otp)
        
        if not send_result["success"]:
            # Mark as failed if SMS couldn't be sent
            otp_record.status = OTPStatus.EXPIRED
            self.db.commit()
            
            return (
                False,
                send_result.get("message", "Failed to send OTP"),
                None,
                None
            )
        
        logger.info(f"OTP sent to {mobile_number}")
        
        return (
            True,
            "OTP sent successfully",
            self.otp_expiry_minutes * 60,  # Convert to seconds
            None
        )
    
    # -------------------------------------------------------------------------
    # Verify OTP
    # -------------------------------------------------------------------------
    
    def verify_otp(
        self, 
        mobile_number: str, 
        otp: str
    ) -> Tuple[bool, str, Optional[User], Optional[str], bool]:
        """
        Verify OTP and authenticate user.
        
        Process:
        1. Find latest pending OTP for mobile number
        2. Check expiry and attempts
        3. Verify OTP hash
        4. On success: create user if new, generate JWT
        
        Args:
            mobile_number: User's mobile number
            otp: OTP entered by user
        
        Returns:
            Tuple of:
            - success (bool): Whether verification succeeded
            - message (str): Status message
            - user (User or None): User object if verified
            - token (str or None): JWT token if verified
            - is_new_user (bool): Whether user was just created
        """
        # Get latest pending OTP record
        otp_record = self._get_pending_otp(mobile_number)
        
        if not otp_record:
            return (
                False,
                "No pending OTP found. Please request a new OTP.",
                None,
                None,
                False
            )
        
        # Check if OTP is still valid
        if otp_record.is_expired:
            otp_record.status = OTPStatus.EXPIRED
            self.db.commit()
            
            return (
                False,
                "OTP has expired. Please request a new OTP.",
                None,
                None,
                False
            )
        
        # Check if attempts exhausted
        if otp_record.is_exhausted:
            otp_record.status = OTPStatus.EXHAUSTED
            self.db.commit()
            
            return (
                False,
                "Maximum attempts exceeded. Please request a new OTP.",
                None,
                None,
                False
            )
        
        # Increment attempt counter
        otp_record.attempts += 1
        self.db.commit()
        
        # Verify OTP hash
        if not verify_otp_hash(otp, otp_record.otp_hash):
            attempts_remaining = otp_record.max_attempts - otp_record.attempts
            
            if attempts_remaining <= 0:
                otp_record.status = OTPStatus.EXHAUSTED
                self.db.commit()
                
                return (
                    False,
                    "Maximum attempts exceeded. Please request a new OTP.",
                    None,
                    None,
                    False
                )
            
            return (
                False,
                f"Incorrect OTP. {attempts_remaining} attempts remaining.",
                None,
                None,
                False
            )
        
        # OTP verified successfully
        otp_record.status = OTPStatus.VERIFIED
        otp_record.verified_at = datetime.utcnow()
        self.db.commit()
        
        # Get or create user
        user, is_new_user = self._get_or_create_user(mobile_number)
        
        # Update last login
        user.last_login_at = datetime.utcnow()
        self.db.commit()
        
        # Generate JWT token
        token = jwt_service.create_access_token(user)
        
        logger.info(
            f"User {user.id} authenticated successfully "
            f"(new_user={is_new_user})"
        )
        
        return (
            True,
            "OTP verified successfully",
            user,
            token,
            is_new_user
        )
    
    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    
    def _check_resend_cooldown(self, mobile_number: str) -> int:
        """
        Check if resend cooldown is active.
        
        Returns seconds remaining, or 0 if can resend.
        """
        # Find most recent OTP for this number
        recent_otp = self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == mobile_number
        ).order_by(
            OTPRecord.created_at.desc()
        ).first()
        
        if not recent_otp:
            return 0
        
        # Calculate time since last OTP
        time_since = datetime.utcnow() - recent_otp.created_at
        cooldown_remaining = self.resend_cooldown - time_since.total_seconds()
        
        return max(0, int(cooldown_remaining))
    
    def _invalidate_pending_otps(self, mobile_number: str) -> None:
        """
        Invalidate all pending OTPs for a mobile number.
        
        Called before generating a new OTP to ensure only
        the latest OTP is valid.
        """
        self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == mobile_number,
            OTPRecord.status == OTPStatus.PENDING
        ).update({
            OTPRecord.status: OTPStatus.EXPIRED
        })
        self.db.commit()
    
    def _get_pending_otp(self, mobile_number: str) -> Optional[OTPRecord]:
        """
        Get the latest pending OTP for a mobile number.
        """
        return self.db.query(OTPRecord).filter(
            OTPRecord.mobile_number == mobile_number,
            OTPRecord.status == OTPStatus.PENDING
        ).order_by(
            OTPRecord.created_at.desc()
        ).first()
    
    def _get_user_by_mobile(self, mobile_number: str) -> Optional[User]:
        """
        Get user by mobile number.
        """
        return self.db.query(User).filter(
            User.mobile_number == mobile_number
        ).first()
    
    def _get_or_create_user(
        self, 
        mobile_number: str,
        default_role: UserRole = UserRole.PATIENT
    ) -> Tuple[User, bool]:
        """
        Get existing user or create new one.
        
        Returns:
            Tuple of (user, is_new_user)
        """
        user = self._get_user_by_mobile(mobile_number)
        
        if user:
            return (user, False)
        
        # Create new user with default role
        new_user = User(
            mobile_number=mobile_number,
            role=default_role,
            is_active=True
        )
        
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
        
        logger.info(f"New user created: {new_user.id}")
        
        return (new_user, True)
