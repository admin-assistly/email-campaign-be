# auth/middleware.py
# Authentication middleware for protecting routes

from functools import wraps
from flask import request, jsonify, session, current_app

def require_auth(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"🔍 [AUTH-MIDDLEWARE] Checking auth for {request.method} {request.path}")
        print(f"🔍 [AUTH-MIDDLEWARE] Session contents: {dict(session)}")
        print(f"🔍 [AUTH-MIDDLEWARE] Request cookies: {dict(request.cookies)}")
        print(f"🔍 [AUTH-MIDDLEWARE] Session ID: {session.sid if hasattr(session, 'sid') else 'No sid'}")
        print(f"🔍 [AUTH-MIDDLEWARE] All headers: {dict(request.headers)}")
        
        if 'user_email' not in session:
            print(f"❌ [AUTH-MIDDLEWARE] No user_email in session")
            return jsonify({"error": "Authentication required"}), 401
        
        print(f"✅ [AUTH-MIDDLEWARE] User authenticated: {session['user_email']}")
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_email():
    """Get the current user's email from session"""
    return session.get('user_email')

def get_current_user_id():
    """Get the current user's ID from session or database"""
    # First try to get from session
    user_id = session.get('user_id')
    if user_id:
        return user_id
    
    # Fallback to database lookup
    user_email = get_current_user_email()
    if not user_email:
        return None
    
    try:
        from db.postgres import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s", (user_email,))
        result = cur.fetchone()
        
        if result:
            user_id = result[0]
            # Store in session for future use
            session['user_id'] = user_id
            return user_id
        return None
    except Exception as e:
        print(f"Error getting user ID: {e}")
        return None
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def validate_user_owns_campaign(campaign_id):
    """Validate that the current user owns the campaign"""
    from db.postgres import get_db_connection
    
    user_id = get_current_user_id()
    if not user_id:
        return False, "User not authenticated"
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT created_by FROM campaigns WHERE id = %s", (campaign_id,))
        result = cur.fetchone()
        
        if not result:
            return False, "Campaign not found"
        
        campaign_owner_id = result[0]
        if campaign_owner_id != user_id:
            return False, "Access denied: You don't own this campaign"
        
        return True, None
        
    except Exception as e:
        print(f"Error validating campaign ownership: {e}")
        return False, "Database error"
    finally:
        cur.close()
        conn.close()
