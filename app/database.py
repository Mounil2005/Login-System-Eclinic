"""
Database Configuration
=======================
SQLAlchemy database connection and session management.
Connects to Supabase PostgreSQL database.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import settings

# ---------------------------------------------------------------------------
# Database Engine
# ---------------------------------------------------------------------------
# Create SQLAlchemy engine with connection pooling.
# pool_pre_ping ensures connections are validated before use.
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Verify connection is alive before using
    pool_size=5,         # Number of connections to keep in pool
    max_overflow=10,     # Additional connections allowed beyond pool_size
    echo=settings.DEBUG  # Log SQL queries in debug mode
)

# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------
# Create a configured session class for database operations.
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# ---------------------------------------------------------------------------
# Base Model Class
# ---------------------------------------------------------------------------
# All database models will inherit from this base class.
Base = declarative_base()


def get_db():
    """
    Database session dependency for FastAPI.
    
    Creates a new database session for each request and ensures
    it's properly closed after the request completes.
    
    Yields:
        Session: SQLAlchemy database session
        
    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
