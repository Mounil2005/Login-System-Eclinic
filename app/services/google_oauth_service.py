"""
Google OAuth Service
===================
Service for handling Google OAuth 2.0 authentication flow.

This service handles:
1. OAuth URL generation
2. Authorization code exchange
3. User info extraction from Google
4. Profile completion flow
"""

import logging
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import httpx

from app.config import settings

# Configure logging
logger = logging.getLogger(__name__)


class GoogleOAuthService:
    """
    Service for Google OAuth 2.0 authentication.
    
    Handles the complete OAuth flow:
    1. Generate authorization URL
    2. Exchange authorization code for access token
    3. Get user profile information from Google
    """
    
    # Google OAuth 2.0 endpoints
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    # Required OAuth scopes
    SCOPES = [
        "openid",
        "email", 
        "profile"
    ]
    
    def __init__(self):
        """Initialize Google OAuth service with configuration."""
        self.client_id = settings.GOOGLE_CLIENT_ID
        self.client_secret = settings.GOOGLE_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_REDIRECT_URI
        
        # Validate configuration
        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            logger.warning(
                "Google OAuth not fully configured. "
                "Some fields are missing in settings."
            )
    
    def generate_auth_url(self, state: Optional[str] = None) -> str:
        """
        Generate Google OAuth authorization URL.
        
        Args:
            state: Optional state parameter for CSRF protection
        
        Returns:
            str: Complete authorization URL to redirect user to
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.SCOPES),
            "response_type": "code",
            "access_type": "offline",
            "prompt": "select_account",  # Always show account selection
        }
        
        if state:
            params["state"] = state
        
        auth_url = f"{self.AUTHORIZATION_URL}?{urlencode(params)}"
        logger.info(f"Generated Google OAuth URL for client_id: {self.client_id}")
        
        return auth_url
    
    async def exchange_code_for_token(self, authorization_code: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.
        
        Args:
            authorization_code: The code returned by Google OAuth
        
        Returns:
            dict: Token response from Google
            
        Raises:
            Exception: If token exchange fails
        """
        token_data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": authorization_code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.TOKEN_URL,
                    data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=30.0
                )
                response.raise_for_status()
                
                token_info = response.json()
                logger.info("Successfully exchanged authorization code for token")
                return token_info
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Token exchange failed: {e.response.text}")
            raise Exception(f"Token exchange failed: {e.response.status_code}")
        except Exception as e:
            logger.error(f"Token exchange error: {str(e)}")
            raise Exception(f"Token exchange error: {str(e)}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user profile information from Google.
        
        Args:
            access_token: Access token from token exchange
        
        Returns:
            dict: User profile information
            
        Raises:
            Exception: If user info retrieval fails
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.USERINFO_URL,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                user_info = response.json()
                logger.info(f"Retrieved user info for Google ID: {user_info.get('id')}")
                return user_info
                
        except httpx.HTTPStatusError as e:
            logger.error(f"User info retrieval failed: {e.response.text}")
            raise Exception(f"User info retrieval failed: {e.response.status_code}")
        except Exception as e:
            logger.error(f"User info retrieval error: {str(e)}")
            raise Exception(f"User info retrieval error: {str(e)}")
    
    async def complete_oauth_flow(self, authorization_code: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Complete the OAuth flow: exchange code and get user info.
        
        Args:
            authorization_code: Authorization code from Google callback
        
        Returns:
            Tuple of:
            - success (bool): Whether OAuth flow completed successfully
            - message (str): Success or error message
            - user_info (dict or None): User profile data if successful
        """
        try:
            # Step 1: Exchange code for token
            token_info = await self.exchange_code_for_token(authorization_code)
            
            if "access_token" not in token_info:
                return False, "No access token received", None
            
            # Step 2: Get user profile
            user_info = await self.get_user_info(token_info["access_token"])
            
            # Validate required fields
            required_fields = ["id", "email", "name"]
            missing_fields = [field for field in required_fields if field not in user_info]
            
            if missing_fields:
                logger.warning(f"Missing required fields from Google: {missing_fields}")
                return False, f"Incomplete profile data: missing {missing_fields}", None
            
            logger.info(f"OAuth flow completed successfully for user: {user_info.get('email')}")
            return True, "OAuth flow completed successfully", user_info
            
        except Exception as e:
            logger.error(f"OAuth flow error: {str(e)}")
            return False, f"OAuth flow failed: {str(e)}", None


# Create service instance
google_oauth_service = GoogleOAuthService()