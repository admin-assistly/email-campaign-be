# auth/routes.py
# Authentication-related routes
# Moved from original app.py: signup, login, logout, password reset, session check

from flask import Blueprint, request, jsonify, session, current_app, redirect
from auth.utils import (
    hash_password,
    verify_password,
    validate_email_format,
    validate_password_strength,
    verify_email_identity
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api")

# --- OAuth Callback Handler ---
@auth_bp.route('/auth/microsoft/callback', methods=['GET'])
def microsoft_oauth_callback():
    """Handle Microsoft OAuth callback and store tokens"""
    code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    state = request.args.get('state')
    
    print(f"OAuth Callback - Code: {code}, Error: {error}, State: {state}")
    
    if error:
        print(f"OAuth Error: {error} - {error_description}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=" + error)
    
    if not code:
        return redirect("http://localhost:3000/oauth-callback?success=false&error=no_code")
    
    try:
        # Decode email from state
        import base64
        email = None
        if state:
            try:
                email = base64.b64decode(state.encode()).decode()
            except Exception as e:
                print(f"Error decoding state: {e}")
        
        if not email:
            email = session.get('oauth_email')
        
        if not email:
            print("No email found in state or session")
            return redirect("http://localhost:3000/oauth-callback?success=false&error=no_email")
        
        # Exchange code for tokens
        import os
        import requests
        from datetime import datetime, timedelta
        from db.postgres import get_db_connection
        
        client_id = os.environ.get('MICROSOFT_CLIENT_ID')
        client_secret = os.environ.get('MICROSOFT_CLIENT_SECRET')
        tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID')
        
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:5000/api/auth/microsoft/callback'
        }
        
        response = requests.post(token_url, data=token_data)
        
        if response.status_code != 200:
            print(f"Token exchange failed: {response.status_code} - {response.text}")
            return redirect("http://localhost:3000/oauth-callback?success=false&error=token_exchange_failed")
        
        token_response = response.json()
        access_token = token_response.get('access_token')
        refresh_token = token_response.get('refresh_token')
        expires_in = token_response.get('expires_in', 3600)
        
        # Calculate expiry time
        expiry_time = datetime.now() + timedelta(seconds=expires_in)
        
        # Store tokens in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID from session or create a placeholder
        user_id = session.get('user_id')
        if not user_id:
            # Try to get user ID from email
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user_result = cursor.fetchone()
            user_id = user_result[0] if user_result else None
        
        if user_id:
            # Insert or update user email account
            cursor.execute("""
                INSERT INTO user_email_accounts 
                (user_id, email_address, provider_type, access_token, refresh_token, token_expiry, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, email_address) 
                DO UPDATE SET 
                    access_token = EXCLUDED.access_token,
                    refresh_token = EXCLUDED.refresh_token,
                    token_expiry = EXCLUDED.token_expiry,
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
            """, (user_id, email, 'microsoft', access_token, refresh_token, expiry_time, True))
            
            conn.commit()
            print(f"Stored OAuth tokens for user {user_id}, email {email}")
        
        cursor.close()
        conn.close()
        
        # Clear session data
        session.pop('oauth_email', None)
        
        return redirect("http://localhost:3000/oauth-callback?success=true&provider=microsoft&email=" + email)
        
    except Exception as e:
        print(f"Error processing OAuth callback: {e}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=processing_error")

# --- Signup ---
@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email', '').strip()
    password = data.get('password', '')
    repeat_password = data.get('repeatPassword', '')
    security_question = data.get('securityQuestion', '')
    security_answer = data.get('securityAnswer', '').strip()

    if not email: return jsonify({"success": False, "message": "Email is required."}), 400
    is_email_valid, email_msg = validate_email_format(email)
    if not is_email_valid: return jsonify({"success": False, "message": email_msg}), 400
    if not password: return jsonify({"success": False, "message": "Password is required."}), 400
    is_password_strong, pwd_strength_msg = validate_password_strength(password)
    if not is_password_strong: return jsonify({"success": False, "message": pwd_strength_msg}), 400
    if password != repeat_password: return jsonify({"success": False, "message": "Passwords do not match."}), 400
    
    if not security_question or security_question == "-- Select a question --":
        return jsonify({"success": False, "message": "Please select a security question."}), 400
    if not security_answer:
        return jsonify({"success": False, "message": "Please provide an answer to your security question."}), 400

    supabase = current_app.supabase

    try:
        response = supabase.table("users").select("email").eq("email", email).execute()
        if response.data: 
            return jsonify({"success": False, "message": "This email is already registered. Please try logging in instead."}), 409
    except Exception as e:
        print(f"Supabase error during email check: {e}")
        return jsonify({"success": False, "message": "An unexpected error occurred during signup. Please try again later."}), 500

    try:
        hashed_password = hash_password(password)
        hashed_security_answer = hash_password(security_answer.lower())  # Lowercase before hashing

        insert_response = supabase.table("users").insert({
            "email": email,
            "password_hash": hashed_password,
            "security_question": security_question,
            "security_answer_hash": hashed_security_answer
        }).execute()
        
        if insert_response.data:
            ses_initiated = verify_email_identity(current_app.ses_client, email)
            if ses_initiated:
                print(f"SES verification initiated successfully for {email}")
                return jsonify({"success": True, "message": f"Account created! A verification email has been sent to {email}. Please check your inbox and spam folder."}), 201
            else:
                print(f"Warning: SES verification failed for {email}. Manual intervention might be needed.")
                return jsonify({"success": True, "message": f"Account created, but we could not send a verification email to {email} at this moment. Please contact support if you don't receive it."}), 201
        else:
            error_details = str(insert_response)
            print(f"Failed to create account in Supabase: {error_details}")
            return jsonify({"success": False, "message": f"Failed to create account: {error_details}"}), 500

    except Exception as e:
        print(f"Error during sign up process: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred during sign up."}), 500

# --- Login ---
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    print(f"\n🔑 [LOGIN DEBUG] Login attempt for email: {email}")
    print(f"🔑 [LOGIN DEBUG] Request cookies: {dict(request.cookies)}")
    print(f"🔑 [LOGIN DEBUG] Session before login: {dict(session)}")
    
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    is_email_valid, email_msg = validate_email_format(email)
    if not is_email_valid:
        return jsonify({"success": False, "message": email_msg}), 400

    if not password:
        return jsonify({"success": False, "message": "Password is required for login."}), 400

    supabase = current_app.supabase

    try:
        response = supabase.table("users").select("password_hash").eq("email", email).limit(1).execute()

        if not response.data:
            print(f"❌ [LOGIN DEBUG] User not found in database")
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        stored_hash = response.data[0]["password_hash"]

        if verify_password(password, stored_hash):
            # Get user ID from database
            from db.postgres import get_db_connection
            conn = get_db_connection()
            cur = conn.cursor()
            
            try:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                result = cur.fetchone()
                user_id = result[0] if result else None
                
                # Set session data
                session['user_email'] = email
                session['user_id'] = user_id
                session['session_id'] = session.sid if hasattr(session, 'sid') else str(id(session))
                
                print(f"✅ [LOGIN DEBUG] Password verified, setting session")
                print(f"✅ [LOGIN DEBUG] Session after login: {dict(session)}")
                print(f"✅ [LOGIN DEBUG] User ID: {user_id}")

                # Update last_login timestamp
                supabase.table("users").update({"last_login": "NOW()"}).eq("email", email).execute()

                response = jsonify({
                    "success": True, 
                    "message": "Login successful!", 
                    "user_email": email,
                    "user_id": user_id
                }), 200
                print(f"✅ [LOGIN DEBUG] Login response sent")
                print(f"✅ [LOGIN DEBUG] Session cookie: {session.sid if hasattr(session, 'sid') else 'No sid'}")
                print(f"✅ [LOGIN DEBUG] Response cookies: {dict(response.headers)}")
                return response
                
            except Exception as e:
                print(f"❌ [LOGIN DEBUG] Error getting user ID: {e}")
                # Fallback to just setting email
                session['user_email'] = email
                session['session_id'] = session.sid if hasattr(session, 'sid') else str(id(session))
                
                response = jsonify({"success": True, "message": "Login successful!", "user_email": email}), 200
                print(f"✅ [LOGIN DEBUG] Login response sent (fallback)")
                return response
            finally:
                cur.close()
                conn.close()
        else:
            print(f"❌ [LOGIN DEBUG] Password verification failed")
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

    except Exception as e:
        print(f"❌ [LOGIN DEBUG] Error during login: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred during login."}), 500

# --- Logout ---
@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email', None)
    session.pop('user_id', None)
    session.pop('session_id', None)
    session.pop('reset_email', None)
    session.pop('security_question_challenge_started', None)
    session.pop('security_question_passed', None)
    return jsonify({"success": True, "message": "Logged out successfully."}), 200

# --- Forgot Password Request ---
@auth_bp.route('/forgot_password_request', methods=['POST'])
def forgot_password_request():
    data = request.json
    email = data.get('email', '').strip()

    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    is_email_valid, email_msg = validate_email_format(email)
    if not is_email_valid:
        return jsonify({"success": False, "message": email_msg}), 400

    supabase = current_app.supabase

    try:
        response = supabase.table("users").select("security_question").eq("email", email).limit(1).execute()

        if response.data and response.data[0]["security_question"]:
            question = response.data[0]["security_question"]
            session['reset_email'] = email
            session['security_question_challenge_started'] = True
            return jsonify({"success": True, "question": question, "message": "Security question retrieved. Please provide your answer."}), 200
        else:
            return jsonify({"success": False, "message": "Invalid email or no security question set for this account."}), 404

    except Exception as e:
        print(f"Error in /forgot_password_request: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500

# --- Verify Security Answer ---
@auth_bp.route('/verify_security_answer', methods=['POST'])
def verify_security_answer():
    data = request.json
    answer = data.get('securityAnswer', '').strip()

    email = session.get('reset_email')
    if not email or not session.get('security_question_challenge_started'):
        return jsonify({"success": False, "message": "Please start the password reset process from the beginning."}), 400
    
    if not answer:
        return jsonify({"success": False, "message": "Security answer is required."}), 400

    supabase = current_app.supabase

    try:
        response = supabase.table("users").select("security_answer_hash").eq("email", email).limit(1).execute()

        if not response.data or not response.data[0]["security_answer_hash"]:
            return jsonify({"success": False, "message": "Invalid email or security answer."}), 404

        stored_answer_hash = response.data[0]["security_answer_hash"]
        
        if verify_password(answer.lower(), stored_answer_hash):
            session['security_question_passed'] = True
            return jsonify({"success": True, "message": "Security question verified. You can now reset your password."}), 200
        else:
            return jsonify({"success": False, "message": "Invalid security answer."}), 401

    except Exception as e:
        print(f"Error in /verify_security_answer: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500

# --- Reset Password ---
@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    new_password = data.get('newPassword', '')
    confirm_password = data.get('confirmPassword', '')

    email = session.get('reset_email')
    if not email or not session.get('security_question_passed'):
        return jsonify({"success": False, "message": "Unauthorized reset attempt. Please complete the security challenge first."}), 403

    if not new_password:
        return jsonify({"success": False, "message": "New password cannot be empty."}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match."}), 400

    is_password_strong, pwd_strength_msg = validate_password_strength(new_password)
    if not is_password_strong:
        return jsonify({"success": False, "message": pwd_strength_msg}), 400

    supabase = current_app.supabase

    try:
        response = supabase.table("users").select("password_hash").eq("email", email).limit(1).execute()

        if not response.data:
            return jsonify({"success": False, "message": "User not found."}), 404

        current_hash = response.data[0]["password_hash"]

        if verify_password(new_password, current_hash):
            return jsonify({"success": False, "message": "New password must be different from the old password."}), 400

        hashed_new_password = hash_password(new_password)

        update_user_response = supabase.table("users").update({"password_hash": hashed_new_password}).eq("email", email).execute()

        if update_user_response.data:
            session.pop('reset_email', None)
            session.pop('security_question_challenge_started', None)
            session.pop('security_question_passed', None)
            return jsonify({"success": True, "message": "Your password has been reset successfully! You can now log in with your new password."}), 200
        else:
            error_details = str(update_user_response)
            print(f"Failed to update password in Supabase: {error_details}")
            return jsonify({"success": False, "message": f"Failed to update password: {error_details}"}), 500

    except Exception as e:
        print(f"[ERROR] Error resetting password: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred during password reset."}), 500

# --- Check Session ---
@auth_bp.route('/check_session', methods=['GET'])
def check_session():
    print(f"\n🔍 [CHECK-SESSION] Session contents: {dict(session)}")
    print(f"🔍 [CHECK-SESSION] 'user_email' in session: {'user_email' in session}")
    print(f"🔍 [CHECK-SESSION] Request cookies: {dict(request.cookies)}")
    print(f"🔍 [CHECK-SESSION] Available session keys: {list(session.keys())}")
    
    if 'user_email' in session:
        print(f"✅ [CHECK-SESSION] User found in session: {session['user_email']}")
        
        # Get user verification status from database
        supabase = current_app.supabase
        try:
            # Check if email_verified column exists, if not default to True for now
            response = supabase.table("users").select("*").eq("email", session['user_email']).limit(1).execute()
            if response.data and "email_verified" in response.data[0]:
                email_verified = response.data[0]["email_verified"]
            else:
                email_verified = True  # Default to True if column doesn't exist
            print(f"✅ [CHECK-SESSION] Email verified status: {email_verified}")
        except Exception as e:
            print(f"❌ [CHECK-SESSION] Error getting email verification: {e}")
            email_verified = True  # Default to True on error
        
        return jsonify({
            "isLoggedIn": True, 
            "data": {
                "user_email": session['user_email'],
                "user_id": session.get('user_id'),
                "session_id": session.get('session_id'),
                "email_verified": email_verified
            }
        }), 200
    
    print(f"❌ [CHECK-SESSION] No user_email in session")
    return jsonify({"isLoggedIn": False, "data": None}), 200

# --- Verify Email ---
@auth_bp.route('/verify_email', methods=['POST'])
def verify_email():
    """Verify user's email address using verification token"""
    data = request.json
    token = data.get('token', '').strip()
    
    if not token:
        return jsonify({"success": False, "message": "Verification token is required."}), 400
    
    supabase = current_app.supabase
    
    try:
        # Find user by verification token
        response = supabase.table("users").select("email, verification_token").eq("verification_token", token).limit(1).execute()
        
        if not response.data:
            return jsonify({"success": False, "message": "Invalid or expired verification token."}), 400
        
        user_email = response.data[0]["email"]
        
        # Update user verification status
        update_response = supabase.table("users").update({
            "email_verified": True,
            "email_verified_at": "NOW()",
            "verification_token": None  # Clear the token after use
        }).eq("email", user_email).execute()
        
        if update_response.data:
            return jsonify({
                "success": True, 
                "message": f"Email {user_email} has been verified successfully!"
            }), 200
        else:
            return jsonify({"success": False, "message": "Failed to update verification status."}), 500
            
    except Exception as e:
        print(f"Error during email verification: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500

# --- Resend Verification Email ---
@auth_bp.route('/resend_verification', methods=['POST'])
def resend_verification():
    """Resend verification email to user"""
    data = request.json
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400
    
    supabase = current_app.supabase
    
    try:
        # Check if user exists and needs verification
        response = supabase.table("users").select("email_verified").eq("email", email).limit(1).execute()
        
        if not response.data:
            return jsonify({"success": False, "message": "User not found."}), 404
        
        if response.data[0]["email_verified"]:
            return jsonify({"success": False, "message": "Email is already verified."}), 400
        
        # Generate new verification token
        import secrets
        verification_token = secrets.token_urlsafe(32)
        
        # Update user with new token
        update_response = supabase.table("users").update({
            "verification_token": verification_token
        }).eq("email", email).execute()
        
        if update_response.data:
            # Send verification email
            ses_initiated = verify_email_identity(current_app.ses_client, email)
            if ses_initiated:
                return jsonify({
                    "success": True, 
                    "message": f"Verification email has been resent to {email}."
                }), 200
            else:
                return jsonify({
                    "success": False, 
                    "message": "Failed to send verification email. Please try again later."
                }), 500
        else:
            return jsonify({"success": False, "message": "Failed to generate verification token."}), 500
            
    except Exception as e:
        print(f"Error resending verification: {e}")
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500

# --- Get Verified User Emails ---
@auth_bp.route('/users/verified-emails', methods=['GET'])
def get_verified_user_emails():
    """Get all verified user emails for IMAP fetcher"""
    supabase = current_app.supabase
    
    try:
        # Get all users with verified emails
        response = supabase.table("users").select("email").eq("email_verified", True).execute()
        
        if response.data:
            verified_emails = [user["email"] for user in response.data]
            return jsonify(verified_emails), 200
        else:
            return jsonify([]), 200
            
    except Exception as e:
        print(f"Error getting verified user emails: {e}")
        return jsonify([]), 500
