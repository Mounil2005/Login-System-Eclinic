"""
E-Clinic Authentication Service
================================
Main entry point for the FastAPI application.

This service provides centralized authentication for the E-Clinic
healthcare platform, supporting both web and mobile clients.

Run with: uvicorn main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import auth

# ---------------------------------------------------------------------------
# Create Database Tables
# ---------------------------------------------------------------------------
# This creates all tables defined in models.py if they don't exist.
# In production, consider using Alembic for migrations.
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Initialize FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="E-Clinic Authentication Service",
    description="""
    Centralized authentication API for the E-Clinic healthcare platform.
    
    ## Features
    - Mobile Number + OTP Authentication
    - JWT Token Management
    - Role-Based Access Control
    
    ## Supported Clients
    - React Web Application
    - React Native Mobile Application
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# CORS Middleware Configuration
# ---------------------------------------------------------------------------
# Configure CORS for web and mobile client access.
# In production, replace "*" with specific allowed origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Include Routers
# ---------------------------------------------------------------------------
# Mount the authentication router with API versioning
app.include_router(
    auth.router,
    prefix=f"/api/{settings.API_VERSION}",
    tags=["Authentication"],
)

# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for load balancers and monitoring.
    
    Returns:
        dict: Service health status
    """
    return {
        "status": "healthy",
        "service": "e-clinic-auth",
        "version": "1.0.0"
    }


@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint with API information.
    
    Returns:
        dict: API welcome message and documentation links
    """
    return {
        "message": "E-Clinic Authentication Service",
        "documentation": "/docs",
        "health": "/health"
    }
