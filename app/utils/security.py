"""
Security Utilities
===================
Cryptographic and security-related utility functions.

All sensitive data (OTPs, passwords) must be hashed before storage.
"""

import secrets
import string
from passlib.context import CryptContext

# ---------------------------------------------------------------------------
# Password/OTP Hashing Context
# ---------------------------------------------------------------------------
# Using bcrypt for secure hashing with automatic salt generation.
# This is suitable for OTPs and passwords.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Adjust for your security/performance needs
)


def generate_otp(length: int = 6) -> str:
    """
    Generate a cryptographically secure random OTP.
    
    Uses secrets module for cryptographic randomness,
    which is essential for security-sensitive applications.
    
    Args:
        length: Number of digits in OTP (default: 6)
    
    Returns:
        str: Random numeric OTP
        
    Example:
        >>> otp = generate_otp()
        >>> len(otp)
        6
        >>> otp.isdigit()
        True
    """
    # Use secrets.choice for cryptographic randomness
    digits = string.digits
    otp = ''.join(secrets.choice(digits) for _ in range(length))
    return otp


def hash_otp(otp: str) -> str:
    """
    Hash an OTP using bcrypt.
    
    OTPs should NEVER be stored in plain text.
    This function creates a secure, salted hash.
    
    Args:
        otp: Plain text OTP to hash
    
    Returns:
        str: Bcrypt hash of the OTP
        
    Security Note:
        - Each hash includes a unique salt
        - Same OTP will produce different hashes
        - Use verify_otp_hash() to check OTPs
    """
    return pwd_context.hash(otp)


def verify_otp_hash(plain_otp: str, hashed_otp: str) -> bool:
    """
    Verify an OTP against its hash.
    
    This is a constant-time comparison to prevent timing attacks.
    
    Args:
        plain_otp: The OTP entered by user
        hashed_otp: The stored hash to verify against
    
    Returns:
        bool: True if OTP matches, False otherwise
        
    Example:
        >>> otp = "123456"
        >>> hashed = hash_otp(otp)
        >>> verify_otp_hash("123456", hashed)
        True
        >>> verify_otp_hash("654321", hashed)
        False
    """
    try:
        return pwd_context.verify(plain_otp, hashed_otp)
    except Exception:
        # Return False on any verification error
        # (malformed hash, etc.)
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Useful for session tokens, CSRF tokens, etc.
    
    Args:
        length: Number of bytes (output will be 2x in hex)
    
    Returns:
        str: Hex-encoded random token
    """
    return secrets.token_hex(length)
