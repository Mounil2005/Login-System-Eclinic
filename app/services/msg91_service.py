"""
MSG91 SMS Service
==================
Integration with MSG91 for sending OTP SMS messages.

MSG91 Documentation: https://docs.msg91.com/
"""

import logging
from typing import Optional, Dict, Any
import httpx

from app.config import settings

# Configure logging
logger = logging.getLogger(__name__)


class MSG91Service:
    """
    Service for sending SMS via MSG91.
    
    MSG91 is an India-focused SMS gateway provider.
    This service handles OTP delivery for authentication.
    """
    
    # MSG91 API endpoints
    BASE_URL = "https://control.msg91.com/api/v5"
    SEND_OTP_URL = f"{BASE_URL}/otp"
    SEND_SMS_URL = f"{BASE_URL}/flow"
    
    def __init__(self):
        """Initialize MSG91 service with configuration."""
        self.auth_key = settings.MSG91_AUTH_KEY
        self.template_id = settings.MSG91_TEMPLATE_ID
        self.sender_id = settings.MSG91_SENDER_ID
        
        # Validate configuration
        if not self.auth_key:
            logger.warning(
                "MSG91_AUTH_KEY not configured. "
                "SMS sending will be simulated in development."
            )
    
    async def send_otp(
        self, 
        mobile_number: str, 
        otp: str
    ) -> Dict[str, Any]:
        """
        Send OTP via MSG91 SMS.
        
        Uses MSG91's Flow API to send templated SMS.
        
        Args:
            mobile_number: Recipient mobile number (E.164 format)
            otp: The OTP to send
        
        Returns:
            dict: Result with 'success' and 'message' keys
            
        Note:
            - In development (no auth key), OTP is logged instead
            - In production, SMS is sent via MSG91 API
        """
        # Development mode: simulate SMS sending
        if not self.auth_key or settings.DEBUG:
            logger.info(
                f"[DEV MODE] OTP for {mobile_number}: {otp}"
            )
            return {
                "success": True,
                "message": "OTP sent (development mode)",
                "request_id": "dev-mode-no-request-id"
            }
        
        # Production mode: send via MSG91
        try:
            # Prepare request payload
            # Using MSG91 Flow API format
            payload = {
                "template_id": self.template_id,
                "sender": self.sender_id,
                "short_url": "0",  # Don't shorten URLs
                "mobiles": mobile_number.replace("+", ""),  # Remove + prefix
                "VAR1": otp,  # OTP variable in template
            }
            
            headers = {
                "authkey": self.auth_key,
                "Content-Type": "application/json"
            }
            
            # Send request to MSG91
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.SEND_SMS_URL,
                    json=payload,
                    headers=headers,
                    timeout=30.0
                )
                
                response_data = response.json()
                
                # Check response
                if response.status_code == 200:
                    logger.info(
                        f"OTP sent successfully to {mobile_number}"
                    )
                    return {
                        "success": True,
                        "message": "OTP sent successfully",
                        "request_id": response_data.get("request_id", "")
                    }
                else:
                    logger.error(
                        f"MSG91 error: {response_data}"
                    )
                    return {
                        "success": False,
                        "message": response_data.get(
                            "message", 
                            "Failed to send OTP"
                        ),
                        "error_code": response_data.get("code")
                    }
                    
        except httpx.TimeoutException:
            logger.error("MSG91 request timeout")
            return {
                "success": False,
                "message": "SMS service timeout"
            }
            
        except httpx.RequestError as e:
            logger.error(f"MSG91 request error: {e}")
            return {
                "success": False,
                "message": "SMS service unavailable"
            }
            
        except Exception as e:
            logger.error(f"Unexpected error sending OTP: {e}")
            return {
                "success": False,
                "message": "Failed to send OTP"
            }
    
    async def verify_delivery_status(
        self, 
        request_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check SMS delivery status (optional).
        
        Args:
            request_id: MSG91 request ID from send response
        
        Returns:
            dict: Delivery status or None if not available
        """
        if not self.auth_key:
            return None
            
        # This would query MSG91 for delivery status
        # Implementation depends on MSG91 subscription level
        return None


# Create a singleton instance
msg91_service = MSG91Service()
