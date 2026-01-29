#!/usr/bin/env python
"""
Database migration script to add missing columns
"""
from sqlalchemy import text
from app.database import engine

def migrate():
    """Add missing columns to users table"""
    with engine.begin() as conn:
        columns_to_add = [
            ("email", "VARCHAR(320) UNIQUE"),
            ("google_id", "VARCHAR(100) UNIQUE"),
            ("profile_picture", "VARCHAR(500)"),
            ("full_name", "VARCHAR(100)"),
            ("is_profile_complete", "BOOLEAN DEFAULT FALSE"),
        ]
        
        for col_name, col_type in columns_to_add:
            try:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}"))
                print(f"✅ Added {col_name} column")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"✅ {col_name} column already exists")
                else:
                    print(f"❌ Error adding {col_name}: {e}")

if __name__ == "__main__":
    print("Starting database migration...")
    migrate()
    print("Migration complete!")
