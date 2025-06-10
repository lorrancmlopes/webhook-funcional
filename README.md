# 🚀 Webhook Payment Confirmation Service

A webhook payment confirmation service built with F# and C#, featuring comprehensive security validation, fraud detection, and database persistence.

## 📋 Overview

This project implements a robust webhook service for processing payment confirmations with security features including HMAC signature validation, transaction authenticity verification, data mismatch detection, and automated confirmation retry mechanisms.

## ✨ Key Features

### 🔒 Security & Validation
- **HMAC-SHA256 Signature Validation**: Cryptographic payload integrity verification
- **Transaction Authenticity**: Nonce-based replay protection and request fingerprinting
- **Data Mismatch Detection**: Advanced fraud detection with 13+ validation rules
- **Token-based Authentication**: Secure webhook token validation
- **IP Whitelisting**: Trusted IP address validation

### 🎯 Business Logic (F# Implementation)
- **Functional Programming**: Pure functions for business rule validation
- **Pattern Matching**: Sophisticated data validation patterns
- **Type Safety**: Strong typing for payment processing logic
- **Immutable Data Structures**: Safe concurrent processing

### 💾 Data Management
- **SQLite Database**: Persistent transaction storage
- **Entity Framework Core**: ORM with migrations
- **Duplicate Prevention**: Database-backed transaction uniqueness
- **Comprehensive Auditing**: Full transaction lifecycle tracking

### 🔄 Confirmation System
- **Automatic Retry Logic**: Configurable retry mechanisms
- **Status Tracking**: Real-time confirmation monitoring
- **Statistics Dashboard**: Performance analytics and metrics
- **Error Handling**: Failure management

## 🛠️ Technology Stack

- **Backend**: .NET 9.0, ASP.NET Core
- **Language**: F# (Business Logic) + C# (Web API)
- **Database**: SQLite with Entity Framework Core
- **Testing**: Python with requests library
- **Architecture**: Functional-first with hybrid OOP

## 📦 Installation

### Prerequisites

- **.NET SDK 9.0** or later
- **Python 3.9+** (for running tests)
- **Git** (for cloning the repository)

### Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/lorrancmlopes/webhook-funcional/
   cd webhook-funcional
   ```

2. **Restore .NET Dependencies**
   ```bash
   dotnet restore
   ```

3. **Build the Project**
   ```bash
   dotnet build
   ```

4. **Setup Python Testing Environment** (Optional)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install requests asyncio fastapi uvicorn
   ```

## 🚀 Running the Application

### Start the Webhook Service

```bash
dotnet run --project LoanApp
```

The service will start on `http://localhost:5000` with the following endpoints:

- `POST /webhook` - Main webhook endpoint for payment processing
- `GET /transactions` - List all processed transactions
- `GET /transaction-stats` - Transaction statistics and analytics
- `GET /confirmation-stats` - Confirmation system statistics
- `POST /generate-signature` - Generate HMAC signatures for testing
- `POST /generate-nonce` - Generate nonce for authenticity testing
- `GET /authenticity-status` - Authenticity validation status

### Configuration

The service can be configured through the following constants in `Program.cs`:

```csharp
// Security Configuration
const string WEBHOOK_SECRET = "webhook-secret-key-2024";
const string WEBHOOK_TOKEN = "meu-token-secreto";

// Feature Flags
const bool ENABLE_AUTHENTICITY_CHECKS = true;
const bool ENABLE_STRICT_TIMING = false;

// Confirmation System
const int MAX_CONFIRMATION_RETRIES = 3;
static readonly TimeSpan CONFIRMATION_RETRY_INTERVAL = TimeSpan.FromSeconds(30);
const string CONFIRMATION_ENDPOINT = "http://localhost:5001/confirmar";
```

## 🧪 Testing

The project includes a comprehensive test suite with **46 total tests** across 5 test files:

### Run All Tests

```bash
# Make sure the webhook service is running first
dotnet run --project LoanApp &

# Run individual test suites
python test_webhook.py          # 6/6 tests - Core webhook functionality
python test_authenticity.py     # 11/11 tests - Security validation
python test_data_mismatch.py    # 16/16 tests - Fraud detection
python test_confirmation.py     # 7/7 tests - Confirmation system
python test_integrity_fixed.py  # 6/6 tests - HMAC validation
```

### Test Coverage

- ✅ **Core Webhook Processing**: Payment success/failure scenarios
- ✅ **Security Validation**: Token, signature, nonce verification
- ✅ **Fraud Detection**: 13+ data mismatch validation rules
- ✅ **Confirmation System**: Retry logic and status tracking
- ✅ **Integrity Validation**: HMAC signature verification

## 📡 API Documentation

### Webhook Payload Format

```json
{
  "event": "payment_success",
  "transaction_id": "payment-tx-123456",
  "amount": "99.90",
  "currency": "BRL",
  "timestamp": "2025-06-10T12:00:00Z"
}
```

### Required Headers

```http
Content-Type: application/json
X-Webhook-Token: meu-token-secreto
X-Webhook-Signature: sha256=<hmac-signature>  # Optional but recommended
X-Webhook-Nonce: <uuid>                       # Optional for authenticity
X-Request-ID: req-<timestamp>-<random>        # Optional for tracking
User-Agent: <client-identifier>               # Optional for validation
```

### Response Formats

**Success Response (200)**:
```json
{
  "message": "Transaction processed successfully",
  "transaction_id": "payment-tx-123456",
  "integrity_validated": true,
  "authenticity_validated": true,
  "confirmation_status": "Confirmed",
  "confirmation_attempts": 1
}
```

**Error Response (400)**:
```json
{
  "error": "Authentication failed"
}
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Python Tests  │    │  External APIs  │
│  (Integration)  │    │ (Confirmation)  │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          ▼                      ▼
┌─────────────────────────────────────────┐
│           ASP.NET Core Web API          │
│              (Program.cs)               │
├─────────────────────────────────────────┤
│         F# Business Logic Library       │
│  ┌─────────────┐ ┌─────────────────────┐│
│  │ Authenticity│ │   Data Mismatch     ││
│  │ Validation  │ │    Detection        ││
│  └─────────────┘ └─────────────────────┘│
│  ┌─────────────┐ ┌─────────────────────┐│
│  │  Integrity  │ │   Confirmation      ││
│  │ Validation  │ │     System          ││
│  └─────────────┘ └─────────────────────┘│
└─────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│     SQLite Database + Entity Framework  │
│  • Transaction Records                  │
│  • Audit Trails                         │
│  • Confirmation Status                  │
└─────────────────────────────────────────┘
```

## 🔍 Data Validation Rules

The system implements comprehensive fraud detection with the following validation rules:

### Critical Mismatches (Auto-Cancel)
- Unsupported currencies
- Test transaction patterns
- Short transaction IDs
- Old/future timestamps
- Event-ID mismatches
- Sequential digit patterns
- Zero amounts with success events

### Warning Mismatches (Log Only)
- Large round amounts
- Suspicious patterns
- Currency-amount inconsistencies

## 📊 Database Schema

```sql
CREATE TABLE Transactions (
    Id INTEGER PRIMARY KEY,
    TransactionId TEXT UNIQUE NOT NULL,
    Event TEXT NOT NULL,
    Amount DECIMAL(18,2) NOT NULL,
    Currency TEXT NOT NULL,
    Timestamp DATETIME NOT NULL,
    ProcessedAt DATETIME NOT NULL,
    Status TEXT NOT NULL,
    ErrorMessage TEXT,
    IntegrityValidated BOOLEAN,
    AuthenticityValidated BOOLEAN,
    DataMismatchDetected BOOLEAN,
    Nonce TEXT,
    RequestId TEXT,
    ClientIp TEXT,
    UserAgent TEXT,
    RequestFingerprint TEXT,
    ConfirmationAttempts INTEGER,
    ConfirmedAt DATETIME,
    ConfirmationError TEXT,
    RawPayload TEXT
);
```

## 🚦 Status Monitoring

### Health Check Endpoints

- `GET /transaction-stats` - Database statistics
- `GET /confirmation-stats` - Confirmation system health
- `GET /authenticity-status` - Security feature status

### Logging

The application provides comprehensive logging:
- Request/response logging
- Security audit trails
- Business rule validation logs
- Database operation logs
- Error tracking and debugging

## 🤖 Acknowledgments & AI Assistance

This project was developed with the help of AI tools to accelerate and support the development process.

* **AI assistance** was used to:

  * Generate boilerplate code for the project structure.
  * Draft and refine functional logic and C# API structure.
  * Write commit messages that clearly describe changes.
  * Create and format this `README.md` file.
---
