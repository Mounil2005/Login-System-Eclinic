"""
Configuration Management
=========================
Centralized configuration using Pydantic Settings.
All configuration values are loaded from environment variables.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All sensitive values should be set via .env file or environment variables.
    Never commit actual secrets to version control.
    """
    
    # -------------------------------------------------------------------------
    # Database Configuration
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/eclinic"
    
    # -------------------------------------------------------------------------
    # JWT Configuration
    # -------------------------------------------------------------------------
    JWT_SECRET_KEY: str = "your-super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 1440  # 24 hours
    
    # -------------------------------------------------------------------------
    # MSG91 Configuration
    # -------------------------------------------------------------------------
    MSG91_AUTH_KEY: str = ""
    MSG91_TEMPLATE_ID: str = ""
    MSG91_SENDER_ID: str = "ECLNC"
    
    # -------------------------------------------------------------------------
    # Google OAuth Configuration
    # -------------------------------------------------------------------------
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"
    
    # -------------------------------------------------------------------------
    # OTP Configuration
    # -------------------------------------------------------------------------
    OTP_EXPIRY_MINUTES: int = 5
    OTP_MAX_ATTEMPTS: int = 3
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    
    # Demo OTP for testing (bypass MSG91)
    USE_DEMO_OTP: bool = True  # Set to False when MSG91 is configured
    DEMO_OTP: str = "123456"  # Demo OTP for testing
    
    # -------------------------------------------------------------------------
    # Email OTP Configuration
    # -------------------------------------------------------------------------
    USE_DEMO_EMAIL_OTP: bool = True  # Set to False when email service is configured
    DEMO_EMAIL_OTP: str = "123456"  # Demo email OTP for testing
    
    # -------------------------------------------------------------------------
    # Application Settings
    # -------------------------------------------------------------------------
    DEBUG: bool = True
    API_VERSION: str = "v1"
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Using lru_cache ensures settings are only loaded once,
    improving performance and consistency.
    
    Returns:
        Settings: Application settings instance
    """
    return Settings()


# Global settings instance for easy import
settings = get_settings()
