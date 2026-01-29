# E-Clinic Authentication Service

A centralized REST authentication service for the E-Clinic healthcare platform, built with Python FastAPI.

## Features

- ✅ Mobile Number + OTP Authentication (MSG91)
- ✅ JWT-based Sessions
- ✅ Role-based Access Control (patient, doctor, clinic_admin, lab_assistant)
- ✅ Secure OTP Storage (hashed)
- ✅ OTP Expiry & Retry Limits
- ✅ Platform-agnostic (works with Web & Mobile clients)

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (Supabase)
- **OTP Provider**: MSG91
- **Authentication**: JWT (python-jose)

## Prerequisites

- Python 3.9+
- PostgreSQL database (Supabase)
- MSG91 account for SMS OTP

## Installation & Setup

### 1. Clone and Setup Virtual Environment

```bash
# Navigate to project directory
cd e-clinic-auth

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```env
# Database (Supabase PostgreSQL)
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRY_MINUTES=1440

# MSG91 Configuration
MSG91_AUTH_KEY=your-msg91-auth-key
MSG91_TEMPLATE_ID=your-msg91-template-id
MSG91_SENDER_ID=ECLNC

# OTP Configuration
OTP_EXPIRY_MINUTES=5
OTP_MAX_ATTEMPTS=3
OTP_RESEND_COOLDOWN_SECONDS=60
```

### 4. Initialize Database

```bash
# Run database migrations
python -c "from app.database import engine, Base; from app.models import *; Base.metadata.create_all(bind=engine)"
```

### 5. Run the Server

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/send-otp` | Send OTP to mobile number |
| POST | `/api/v1/auth/verify-otp` | Verify OTP and get JWT token |
| GET | `/api/v1/me` | Get current user info (protected) |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health check |

## Project Structure

```
e-clinic-auth/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (create this)
├── .env.example           # Environment template
├── README.md              # This file
└── app/
    ├── __init__.py
    ├── config.py          # Configuration management
    ├── database.py        # Database connection
    ├── models.py          # SQLAlchemy models
    ├── schemas.py         # Pydantic schemas
    ├── dependencies.py    # FastAPI dependencies
    ├── routers/
    │   ├── __init__.py
    │   └── auth.py        # Authentication routes
    ├── services/
    │   ├── __init__.py
    │   ├── otp_service.py # OTP generation & validation
    │   ├── msg91_service.py # MSG91 SMS integration
    │   └── jwt_service.py # JWT token management
    └── utils/
        ├── __init__.py
        └── security.py    # Security utilities
```

## Security Features

1. **Hashed OTP Storage**: OTPs are never stored in plain text
2. **OTP Expiry**: OTPs expire after 5 minutes (configurable)
3. **Rate Limiting**: Maximum 3 OTP attempts before lockout
4. **Resend Cooldown**: 60-second cooldown between OTP resends
5. **JWT Expiry**: Tokens expire after 24 hours (configurable)

## Roles

- `patient` - Default role for new users
- `doctor` - Healthcare provider
- `clinic_admin` - Clinic administrator
- `lab_assistant` - Laboratory staff

## License

Proprietary - E-Clinic Healthcare Platform
