#!/usr/bin/env python
"""
Check existing tables in the database
"""

from app.database import engine
from sqlalchemy import text

def check_existing_tables():
    """Check what tables already exist in the database."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """))
            
            tables = [row[0] for row in result]
            
            print("📋 Existing tables in your database:")
            if tables:
                for table in tables:
                    print(f"  ✅ {table}")
            else:
                print("  (No public tables found)")
            
            return tables
            
    except Exception as e:
        print(f"❌ Error checking tables: {e}")
        return []

if __name__ == "__main__":
    check_existing_tables()