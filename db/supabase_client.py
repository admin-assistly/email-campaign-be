# db/supabase_client.py
# Supabase client initialization
# Moved from original app.py: Supabase configuration section

import os
from supabase import create_client, Client

def init_supabase() -> Client:
    """
    Initialize and return a Supabase client using environment variables.
    Raises ValueError if required variables are missing.
    """
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL or Key not found in environment variables. Check your .env file.")

    return create_client(supabase_url, supabase_key)
