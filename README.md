# Email Campaign Backend

A dynamic multi-user email campaign platform with OAuth integration for Microsoft accounts.

## 🚀 Features

- **Dynamic OAuth Authentication** - Users connect their own email accounts
- **Multi-User Support** - Each user has their own email credentials
- **Automatic Token Refresh** - OAuth tokens are automatically renewed
- **Email Campaign Management** - Create, send, and track campaigns
- **Response Monitoring** - Capture and classify email responses
- **AI Classification** - Automatically classify response sentiment
- **File Management** - Upload and manage subscriber lists

## 📁 Project Structure

```
email-campaign-backend/
├── app.py                          # Main Flask application
├── config.py                       # Configuration settings
├── requirements.txt                # Python dependencies
├── run_dynamic_imap.py            # Dynamic IMAP fetcher runner
├── imap_fetcher_dynamic.py        # Multi-user IMAP fetcher
├── email_cleaner.py               # Email content cleaning utilities
├── README.md                      # This file
├── .gitignore                     # Git ignore rules
├── flask_session/                 # Flask session storage
├── auth/                          # Authentication routes
├── campaigns/                     # Campaign management
├── responses/                     # Response handling
├── emails/                        # Email management
├── files/                         # File upload handling
├── campaign_files/                # Campaign-file associations
├── classification/                # AI classification
├── email_generation/              # AI email generation
├── email_accounts/                # Email account management
└── db/                           # Database utilities
    ├── postgres.py               # PostgreSQL connection
    ├── supabase_client.py        # Supabase client
```

## 🛠️ Setup Instructions

### 1. Environment Variables

Create a `.env` file with the following variables:

```bash
# Database (Supabase)
DB_HOST=your_supabase_host
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your_supabase_password

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your_client_id
MICROSOFT_CLIENT_SECRET=your_client_secret
MICROSOFT_TENANT_ID=your_tenant_id

# AWS SES
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_REGION=us-east-1
BUCKET_NAME=your_s3_bucket

# Flask
FLASK_SECRET_KEY=your_secret_key

# IMAP Settings
IMAP_POLL_INTERVAL=30
SENT_LOOKBACK_DAYS=7
```

### 2. Database Setup

Run the database schema in Supabase:



### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the Backend

```bash
python app.py
```

### 5. Start Dynamic IMAP Fetcher

```bash
python imap_fetcher_dynamic.py
```

## 🔧 API Endpoints

### Authentication
- `POST /api/signup` - User registration
- `POST /api/login` - User login
- `GET /api/auth/check` - Check authentication status
- `POST /api/logout` - User logout

### Email Accounts
- `GET /api/email-accounts/status` - Check email connection status
- `POST /api/email-accounts/oauth-url` - Get OAuth URL
- `POST /api/email-accounts/disconnect` - Disconnect email account
- `GET /api/auth/microsoft/callback` - OAuth callback handler

### Campaigns
- `GET /api/campaigns` - List campaigns
- `POST /api/campaigns` - Create campaign
- `PUT /api/campaigns/{id}` - Update campaign
- `DELETE /api/campaigns/{id}` - Delete campaign
- `POST /api/campaigns/{id}/send` - Send campaign

### Files
- `POST /api/upload-file` - Upload subscriber list
- `GET /api/files` - List uploaded files
- `GET /api/files/{id}/presigned-url` - Get download URL

### Responses
- `GET /api/responses` - List responses
- `POST /api/responses` - Create response
- `POST /api/responses/{id}/classify` - Classify response

## 🔄 Dynamic IMAP Fetcher

The dynamic IMAP fetcher monitors multiple user email accounts:

- **Multi-user support** - Each user's email account is monitored separately
- **OAuth token management** - Automatic token refresh
- **Response capture** - Captures replies to campaign emails
- **Threading support** - Links responses to original campaigns
- **Duplicate prevention** - Prevents processing duplicate emails

### Running the Fetcher

```bash
python imap_fetcher_dynamic.py
```

The fetcher will:
1. Query the database for active user email accounts
2. Refresh OAuth tokens as needed
3. Connect to each user's mailbox
4. Process new emails and responses
5. Trigger AI classification for responses

## 🔐 Security Features

- **OAuth 2.0** - Secure email account authentication
- **Token encryption** - OAuth tokens stored securely
- **Session management** - Secure user sessions
- **CORS protection** - Cross-origin request protection
- **Input validation** - All inputs validated and sanitized

