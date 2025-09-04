# config.py
# Centralized app configuration and service initialization.
# Moved from top of original app.py — AWS SES/S3 config, Supabase init, Flask session setup.

import os
from dotenv import load_dotenv
from flask_session import Session
import boto3
from db.supabase_client import init_supabase




def init_config(app):
    """
    Initialize environment variables, Flask sessions, AWS clients, and Supabase client.
    This runs once from app.py when the Flask app starts.
    """

    # --- Load environment variables ---
    load_dotenv()

    # --- Flask Secret Key ---
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        raise ValueError("FLASK_SECRET_KEY environment variable not set. Please set it in your .env file.")

    # --- Session Configuration ---
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"  # Consider 'redis' or 'sqlalchemy' for production
    
    # 🔧 FIXED: Add missing session cookie settings
    app.config["SESSION_COOKIE_SECURE"] = False  # Set to True in production
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
    app.config["SESSION_COOKIE_DOMAIN"] = None  # For localhost
    app.config["SESSION_COOKIE_PATH"] = "/"
    
    # 🔧 FIXED: Specify session directory
    app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")
    
    # 🔧 FIXED: Ensure session directory exists
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    
    Session(app)

    # --- AI Email Generation Config ---
    app.config["AI_BASE_URL"] = os.environ.get("AI_BASE_URL", "http://127.0.0.1:8000")
    app.config["AI_API_KEY"] = os.environ.get("AI_API_KEY", "dev_mock_key_12345")
    app.config["INTRO_TASK_ID"] = os.environ.get("INTRO_TASK_ID", "your_intro_task_id")
    app.config["RESPONDER_TASK_ID"] = os.environ.get("RESPONDER_TASK_ID", "your_responder_task_id")
    app.config["TEAM_ID"] = os.environ.get("TEAM_ID", "your_team_id")

    # Prebuilt headers
    app.config["AI_HEADERS"] = {
        "Content-Type": "application/json",
        "X-API-Key": app.config["AI_API_KEY"],
    }


    # --- AWS SES Client Initialization ---
    aws_region = os.getenv("AWS_REGION", "us-east-1")  # Default to us-east-1 if not set
    try:
        # Boto3 will automatically pick up AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from environment variables
        app.ses_client = boto3.client('sesv2', region_name=aws_region)
        print(f"AWS SES client initialized for region: {aws_region}")
    except Exception as e:
        print(f"Warning: Could not initialize AWS SES client. Ensure AWS credentials and region are configured. Error: {e}")
        app.ses_client = None

    # --- Supabase Client Initialization ---
    app.supabase = init_supabase()

    print("Supabase client initialized successfully")
    print(f"Session directory: {app.config['SESSION_FILE_DIR']}")
