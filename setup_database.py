#!/usr/bin/env python
"""
SAFE Database Setup Script
==========================
Creates ONLY the authentication tables (users, otp_records) if they don't exist.
WILL NOT modify or delete any existing tables.
"""

from app.database import engine, Base
from app.models import User, OTPRecord
from sqlalchemy import text
import sys

def check_existing_tables():
    """Check what tables already exist."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """))
            return [row[0] for row in result]
    except Exception as e:
        print(f"❌ Error checking tables: {e}")
        return []

def setup_auth_tables_safely():
    """Create ONLY our auth tables if they don't exist."""
    try:
        existing_tables = check_existing_tables()
        
        print("🔧 Safe database setup for authentication...")
        print(f"📋 Found {len(existing_tables)} existing tables in database")
        
        # Check if our tables already exist
        auth_tables_needed = []
        if 'users' not in existing_tables:
            auth_tables_needed.append('users')
        else:
            print("✅ 'users' table already exists - skipping")
            
        if 'otp_records' not in existing_tables:
            auth_tables_needed.append('otp_records')
        else:
            print("✅ 'otp_records' table already exists - skipping")
        
        if not auth_tables_needed:
            print("🎉 All authentication tables already exist!")
            return True
        
        print(f"📝 Will create these tables: {', '.join(auth_tables_needed)}")
        
        # Create only our specific tables
        with engine.begin() as conn:
            if 'users' in auth_tables_needed:
                User.__table__.create(bind=conn, checkfirst=True)
                print("✅ Created 'users' table")
                
            if 'otp_records' in auth_tables_needed:
                OTPRecord.__table__.create(bind=conn, checkfirst=True)
                print("✅ Created 'otp_records' table")
        
        print("\n🎉 Authentication tables setup completed safely!")
        print("💡 No existing tables were modified or deleted.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating auth tables: {e}")
        return False

def verify_connection():
    """Test database connection."""
    try:
        print("🔌 Testing database connection...")
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("✅ Database connection successful!")
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

if __name__ == "__main__":
    print("E-Clinic Auth - SAFE Database Setup")
    print("=" * 50)
    print("⚠️  This script will ONLY create missing auth tables.")
    print("⚠️  It will NOT modify any existing data or tables.")
    print()
    
    # Test connection first
    if not verify_connection():
        print("\n❌ Please check your database connection string in .env")
        sys.exit(1)
    
    # Create auth tables safely
    if setup_auth_tables_safely():
        print("\n🎉 Setup completed successfully!")
        print("Your existing e-clinic data is completely safe.")
    else:
        print("\n❌ Setup failed. Please check the errors above.")
        sys.exit(1)