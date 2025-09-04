# db/postgres.py
# PostgreSQL connection helper
# Moved from original app.py: get_db_connection() function

import os
import psycopg2
from dotenv import load_dotenv

def get_db_connection():
    """
    Create and return a PostgreSQL database connection using environment variables.
    Configured for Supabase connection pooler with SSL.
    """
    # Load environment variables
    load_dotenv()
    
    # Use individual parameters instead of DATABASE_URL
    host = os.environ.get('DB_HOST')
    port = os.environ.get('DB_PORT')
    dbname = os.environ.get('DB_NAME')
    user = os.environ.get('DB_USER')
    password = os.environ.get('DB_PASSWORD')
    
    print(f"Connecting to DB: {host}:{port}/{dbname} as {user}")

    # Supabase connection pooler requires SSL
    return psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
        sslmode='require'  # Required for Supabase connection pooler
    )
