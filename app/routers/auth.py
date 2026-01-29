"""
Authentication Router
======================
REST API endpoints for authentication operations.

Endpoints:
- POST /auth/send-otp           - Send OTP to mobile number
- POST /auth/verify-otp         - Verify OTP and get JWT token
- GET  /auth/google/login       - Initiate Google OAuth flow
- GET  /auth/google/callback    - Handle Google OAuth callback
- POST /auth/google/complete    - Complete profile for Google users
- GET  /me                      - Get current user info (protected)
"""

from typing import Optional
import secrets
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    SendOTPRequest,
    SendOTPResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
    UserResponse,
    ErrorResponse,
    GoogleAuthURLResponse,
    GoogleCallbackResponse,
    CompleteProfileRequest,
    CompleteProfileResponse,
    SendEmailOTPRequest,
    VerifyEmailOTPRequest
)
from app.services.otp_service import OTPService
from app.services.google_oauth_service import google_oauth_service
from app.services.jwt_service import jwt_service
from app.dependencies import get_current_user
from app.config import settings

# Configure logging
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router Configuration
# ---------------------------------------------------------------------------
router = APIRouter()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> Optional[str]:
    """
    Extract client IP address from request.
    
    Handles X-Forwarded-For header for proxy scenarios.
    """
    # Check for forwarded header first (behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in the list is the client
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return None


def get_user_agent(request: Request) -> Optional[str]:
    """Extract user agent from request headers."""
    return request.headers.get("User-Agent")


# ---------------------------------------------------------------------------
# Send OTP Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/auth/send-otp",
    response_model=SendOTPResponse,
    responses={
        200: {"description": "OTP sent successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        429: {"model": ErrorResponse, "description": "Rate limited"},
        500: {"model": ErrorResponse, "description": "Server error"}
    },
    summary="Send OTP to Mobile Number",
    description="""
    Send a 6-digit OTP to the specified mobile number via SMS.
    
    **Rate Limiting:**
    - 60-second cooldown between OTP requests
    - OTP expires after 5 minutes
    
    **Security:**
    - OTP is NOT returned in the response
    - OTP is stored hashed in the database
    
    **Mobile Format:**
    - Use E.164 format: +91XXXXXXXXXX
    """
)
async def send_otp(
    request_data: SendOTPRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Send OTP to mobile number.
    
    This endpoint:
    1. Validates the mobile number format
    2. Checks for rate limiting (resend cooldown)
    3. Generates a new 6-digit OTP
    4. Stores the OTP hash in database
    5. Sends OTP via MSG91 SMS
    
    The OTP is NEVER included in the response for security.
    """
    # Create OTP service with database session
    otp_service = OTPService(db)
    
    # Get client info for audit
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    # Attempt to send OTP
    success, message, expires_in, resend_in = await otp_service.send_otp(
        mobile_number=request_data.mobile_number,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    # Handle rate limiting
    if not success and resend_in:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "success": False,
                "error": "RATE_LIMITED",
                "message": message,
                "resend_available_in_seconds": resend_in
            }
        )
    
    # Handle other failures
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": "SMS_FAILED",
                "message": message
            }
        )
    
    # Success response
    return SendOTPResponse(
        success=True,
        message=message,
        expires_in_seconds=expires_in or 300,
        resend_available_in_seconds=None
    )


# ---------------------------------------------------------------------------
# Verify OTP Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/auth/verify-otp",
    response_model=VerifyOTPResponse,
    responses={
        200: {"description": "OTP verified, JWT token returned"},
        400: {"model": ErrorResponse, "description": "Invalid OTP or expired"},
        401: {"model": ErrorResponse, "description": "Verification failed"},
        500: {"model": ErrorResponse, "description": "Server error"}
    },
    summary="Verify OTP and Get Token",
    description="""
    Verify the OTP sent to a mobile number and receive a JWT token.
    
    **On Success:**
    - If user exists: Returns JWT token
    - If new user: Creates user with 'patient' role, returns JWT token
    
    **Verification Rules:**
    - Maximum 3 attempts per OTP
    - OTP expires after 5 minutes
    
    **Token Details:**
    - JWT contains: user_id, mobile_number, role, expiry
    - Token expires after 24 hours
    """
)
async def verify_otp(
    request_data: VerifyOTPRequest,
    db: Session = Depends(get_db)
):
    """
    Verify OTP and authenticate user.
    
    This endpoint:
    1. Validates the OTP against stored hash
    2. Checks expiry and attempt limits
    3. Creates new user if first login
    4. Generates and returns JWT token
    """
    # Create OTP service with database session
    otp_service = OTPService(db)
    
    # Verify OTP
    success, message, user, token, is_new_user = otp_service.verify_otp(
        mobile_number=request_data.mobile_number,
        otp=request_data.otp
    )
    
    # Handle failure
    if not success:
        # Determine appropriate status code
        status_code = status.HTTP_401_UNAUTHORIZED
        
        if "expired" in message.lower():
            error_code = "OTP_EXPIRED"
        elif "attempts" in message.lower():
            error_code = "MAX_ATTEMPTS_EXCEEDED"
        elif "incorrect" in message.lower():
            error_code = "INVALID_OTP"
            status_code = status.HTTP_400_BAD_REQUEST
        else:
            error_code = "VERIFICATION_FAILED"
        
        raise HTTPException(
            status_code=status_code,
            detail={
                "success": False,
                "error": error_code,
                "message": message
            }
        )
    
    # Success response
    return VerifyOTPResponse(
        success=True,
        message=message,
        token=token,
        role=user.role.value,
        user_id=str(user.id),
        is_new_user=is_new_user
    )


# ---------------------------------------------------------------------------
# Get Current User Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/me",
    response_model=UserResponse,
    responses={
        200: {"description": "Current user information"},
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Account deactivated"}
    },
    summary="Get Current User",
    description="""
    Get information about the currently authenticated user.
    
    **Requires:** Valid JWT token in Authorization header
    
    **Returns:** User ID, mobile number, role, and account status
    """
)
async def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information.
    
    This is a protected endpoint that requires a valid JWT token.
    Used to verify authentication and get user details.
    """
    return UserResponse(
        user_id=str(current_user.id),
        mobile_number=current_user.mobile_number,
        role=current_user.role.value,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at
    )


# ---------------------------------------------------------------------------
# Token Validation Endpoint (Optional - for debugging)
# ---------------------------------------------------------------------------

@router.get(
    "/auth/validate",
    responses={
        200: {"description": "Token is valid"},
        401: {"description": "Token is invalid"}
    },
    summary="Validate Token",
    description="Check if the current JWT token is valid. Returns 200 if valid, 401 if not."
)
async def validate_token(
    current_user: User = Depends(get_current_user)
):
    """
    Simple endpoint to validate token.
    
    Returns 200 with minimal info if token is valid.
    Useful for client-side token validation.
    """
    return {
        "valid": True,
        "user_id": str(current_user.id),
        "role": current_user.role.value
    }


# ---------------------------------------------------------------------------
# Google OAuth Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/auth/google/login", 
    response_model=GoogleAuthURLResponse,
    summary="Initiate Google OAuth",
    description="Generate Google OAuth authorization URL for user authentication"
)
async def google_login():
    """Start Google OAuth flow."""
    try:
        state = secrets.token_urlsafe(32)
        auth_url = google_oauth_service.generate_auth_url(state=state)
        logger.info("Generated Google OAuth URL")
        return GoogleAuthURLResponse(auth_url=auth_url, state=state)
    except Exception as e:
        logger.error(f"Google OAuth URL generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"success": False, "error": "OAUTH_CONFIG_ERROR", "message": "Google OAuth not configured"}
        )


@router.get(
    "/auth/google/callback",
    response_model=GoogleCallbackResponse, 
    summary="Handle Google OAuth Callback"
)
async def google_callback(
    code: str = Query(...),
    error: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Handle Google OAuth callback."""
    if error:
        raise HTTPException(status_code=400, detail={"error": "OAUTH_ERROR", "message": error})
    
    try:
        success, message, user_info = await google_oauth_service.complete_oauth_flow(code)
        if not success:
            raise HTTPException(status_code=400, detail={"error": "OAUTH_FLOW_ERROR", "message": message})
        
        # Check existing user by Google ID
        existing_user = db.query(User).filter(User.google_id == user_info["id"]).first()
        
        if existing_user:
            # Existing user login
            token = jwt_service.create_access_token(existing_user)
            return GoogleCallbackResponse(
                success=True,
                message="Login successful", 
                token=token,
                user=UserResponse(
                    user_id=str(existing_user.id),
                    mobile_number=existing_user.mobile_number,
                    email=existing_user.email,
                    full_name=existing_user.full_name,
                    profile_picture=existing_user.profile_picture,
                    role=existing_user.role.value,
                    is_active=existing_user.is_active,
                    is_mobile_verified=existing_user.is_mobile_verified,
                    is_profile_complete=existing_user.is_profile_complete,
                    created_at=existing_user.created_at,
                    last_login_at=existing_user.last_login_at
                ),
                requires_profile_completion=False
            )
        else:
            # New user - create partial record
            from app.models import UserRole
            new_user = User(
                email=user_info["email"],
                google_id=user_info["id"], 
                full_name=user_info["name"],
                profile_picture=user_info.get("picture"),
                role=UserRole.PATIENT,
                is_profile_complete=False
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            
            temp_token = jwt_service.create_access_token(new_user)
            return GoogleCallbackResponse(
                success=True,
                message="Profile completion required",
                temp_token=temp_token,
                user_info={"email": user_info["email"], "name": user_info["name"], "picture": user_info.get("picture")},
                requires_profile_completion=True
            )
            
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Google callback error: {str(e)}\n{error_details}")
        raise HTTPException(status_code=500, detail={"error": "CALLBACK_ERROR", "message": f"OAuth callback failed: {str(e)}"})


@router.post(
    "/auth/google/complete",
    response_model=CompleteProfileResponse,
    summary="Complete Google User Profile"
)
async def complete_google_profile(
    request_data: CompleteProfileRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Complete profile for Google OAuth users."""
    if not current_user.google_id:
        raise HTTPException(status_code=400, detail={"error": "NOT_GOOGLE_USER", "message": "Only for Google users"})
    
    # Check mobile number availability
    existing = db.query(User).filter(User.mobile_number == request_data.mobile_number, User.id != current_user.id).first()
    if existing:
        raise HTTPException(status_code=400, detail={"error": "MOBILE_EXISTS", "message": "Mobile number already registered"})
    
    # Update user profile
    current_user.mobile_number = request_data.mobile_number
    current_user.is_profile_complete = True
    db.commit()
    
    # Send OTP for verification
    otp_service = OTPService(db)
    success, message, _, _ = await otp_service.send_otp(request_data.mobile_number)
    
    if not success:
        # Rollback on OTP failure
        current_user.mobile_number = None
        current_user.is_profile_complete = False
        db.commit()
        raise HTTPException(status_code=500, detail={"error": "OTP_FAILED", "message": message})
    
    token = jwt_service.create_access_token(current_user)
    return CompleteProfileResponse(
        success=True,
        message="Profile completed. Verify mobile with OTP.",
        token=token,
        user=UserResponse(
            user_id=str(current_user.id),
            mobile_number=current_user.mobile_number,
            email=current_user.email,
            full_name=current_user.full_name,
            profile_picture=current_user.profile_picture,
            role=current_user.role.value,
            is_active=current_user.is_active,
            is_mobile_verified=False,
            is_profile_complete=True,
            created_at=current_user.created_at,
            last_login_at=current_user.last_login_at
        ),
        is_new_user=True
    )


# ---------------------------------------------------------------------------
# Email OTP Endpoints
# ---------------------------------------------------------------------------

@router.post("/auth/send-email-otp", response_model=SendOTPResponse, summary="Send Email OTP")
async def send_email_otp(request_data: SendEmailOTPRequest, request: Request, db: Session = Depends(get_db)):
    """Send OTP to email address."""
    try:
        from app.services.email_otp_service import EmailOTPService
        
        email_service = EmailOTPService(db)
        success, message, expires_in, resend_wait = await email_service.send_otp(
            request_data.email, 
            get_client_ip(request), 
            get_user_agent(request)
        )
        
        if not success:
            raise HTTPException(
                status_code=429, 
                detail={"success": False, "error": "RATE_LIMITED", "message": message}
            )
        
        return SendOTPResponse(
            success=True, 
            message="OTP sent to email successfully", 
            expires_in_seconds=expires_in or 300,
            resend_available_in_seconds=resend_wait
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email OTP error: {str(e)}")
        raise HTTPException(status_code=500, detail={"success": False, "error": "SERVER_ERROR"})


@router.post("/auth/verify-email-otp", response_model=VerifyOTPResponse, summary="Verify Email OTP")
def verify_email_otp(request_data: VerifyEmailOTPRequest, db: Session = Depends(get_db)):
    """Verify email OTP and get JWT token."""
    try:
        from app.services.email_otp_service import EmailOTPService
        
        email_service = EmailOTPService(db)
        success, message, user, _, is_new = email_service.verify_otp(request_data.email, request_data.otp)
        
        if not success:
            raise HTTPException(
                status_code=401, 
                detail={"success": False, "error": "VERIFICATION_FAILED", "message": message}
            )
        
        token = jwt_service.create_access_token(user)
        
        return VerifyOTPResponse(
            success=True,
            message="Email OTP verified successfully",
            token=token,
            role=user.role.value,
            user_id=str(user.id),
            is_new_user=is_new
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email OTP verify error: {str(e)}")
        raise HTTPException(status_code=500, detail={"success": False, "error": "SERVER_ERROR"})
