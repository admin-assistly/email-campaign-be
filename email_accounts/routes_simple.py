# email_accounts/routes_simple.py
# Enhanced email account management with OAuth token exchange and database storage

from flask import Blueprint, request, jsonify, current_app, redirect, url_for, session
from auth.middleware import require_auth, get_current_user_email, get_current_user_id
from db.postgres import get_db_connection
import json
import os
import requests
import secrets
from datetime import datetime, timedelta
from msal import ConfidentialClientApplication
import base64

email_accounts_bp = Blueprint("email_accounts", __name__, url_prefix="/api")

# --- Email Account Status ---
@email_accounts_bp.route("/email-accounts/status", methods=["GET"])
@require_auth
def get_email_account_status():
    """Get email account connection status for the current user"""
    try:
        user_id = get_current_user_id()
        user_email = get_current_user_email()
        
        # Query database for user's email accounts
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT email_address, provider_type, is_active, created_at, last_synced_at
            FROM user_email_accounts 
            WHERE user_id = %s AND is_active = true
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,))
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            email_address, provider_type, is_active, created_at, last_synced_at = result
            return jsonify({
                "success": True,
                "data": {
                    "connected": True,
                    "email": email_address,
                    "provider_name": provider_type.title(),
                    "provider": provider_type,
                    "created_at": created_at.isoformat() if created_at else None,
                    "last_synced_at": last_synced_at.isoformat() if last_synced_at else None
                }
            }), 200
        else:
            return jsonify({
                "success": True,
                "data": {
                    "connected": False,
                    "email": user_email,
                    "provider": None,
                    "created_at": None
                }
            }), 200
        
    except Exception as e:
        print(f"Error getting email account status: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# --- Detect Email Provider ---
@email_accounts_bp.route("/email-accounts/detect-provider", methods=["POST"])
@require_auth
def detect_email_provider():
    """Detect email provider for a given email address"""
    data = request.json
    email = data.get('email', '').strip()
    print("email testsjsdhksdjvn:", email)
    if not email:
        return jsonify({"error": "Email address is required"}), 400
    
    try:
        # Simple provider detection based on domain
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        if 'outlook.com' in domain or 'hotmail.com' in domain or 'live.com' in domain or 'charterglobal.com' in domain:
            provider_info = {
                "provider": "microsoft",
                "name": "Microsoft 365",
                "auth_method": "oauth",
                "oauth_provider": "microsoft",
                "imap_host": "outlook.office365.com",
                "imap_port": 993,
                "smtp_host": "smtp.office365.com",
                "smtp_port": 587
            }
        elif 'gmail.com' in domain:
            provider_info = {
                "provider": "google",
                "name": "Gmail",
                "auth_method": "oauth",
                "oauth_provider": "google",
                "imap_host": "imap.gmail.com",
                "imap_port": 993,
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587
            }
        elif 'yahoo.com' in domain:
            provider_info = {
                "provider": "yahoo",
                "name": "Yahoo Mail",
                "auth_method": "oauth",
                "oauth_provider": "yahoo",
                "imap_host": "imap.mail.yahoo.com",
                "imap_port": 993,
                "smtp_host": "smtp.mail.yahoo.com",
                "smtp_port": 587
            }
        else:
            # Generic provider for other domains
            provider_info = {
                "provider": "generic",
                "name": "Generic Email Provider",
                "auth_method": "basic_auth",
                "oauth_provider": None,
                "imap_host": f"imap.{domain}",
                "imap_port": 993,
                "smtp_host": f"smtp.{domain}",
                "smtp_port": 587
            }
        
        return jsonify({
            "success": True,
            "data": provider_info
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# --- Get OAuth URL ---
@email_accounts_bp.route("/email-accounts/oauth-url", methods=["POST"])
@require_auth
def get_oauth_url():
    """Get OAuth authorization URL for email provider"""
    data = request.json
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({"error": "Email address is required"}), 400
    
    try:
        # For now, return a placeholder OAuth URL
        # This should be replaced with actual OAuth implementation
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        if 'outlook.com' in domain or 'hotmail.com' in domain or 'live.com' in domain or 'charterglobal.com' in domain:
            # Microsoft OAuth URL with actual client ID
            client_id = os.environ.get('MICROSOFT_CLIENT_ID')
            if not client_id:
                return jsonify({
                    "error": "Microsoft OAuth not configured. Please set MICROSOFT_CLIENT_ID in environment variables."
                }), 500
            
            # Check if we have a tenant ID for single-tenant mode
            tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID')
            
            if tenant_id:
                # Use tenant-specific endpoint for single-tenant apps
                auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            else:
                # Use common endpoint for multi-tenant apps
                auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            
            # Store email in session for OAuth callback
            session['oauth_email'] = email
            
            # Create state parameter with expected email
            state_data = {
                "expected_email": email,
                "nonce": secrets.token_urlsafe(16)
            }
            state_json = json.dumps(state_data)
            # URL-encode the state to avoid odd characters
            import urllib.parse
            state_encoded = urllib.parse.quote(state_json)
            
            auth_url += f"?client_id={client_id}"
            auth_url += "&response_type=code"
            auth_url += "&redirect_uri=http://localhost:5000/api/auth/microsoft/callback"
            auth_url += "&scope=https://outlook.office365.com/IMAP.AccessAsUser.All%20https://outlook.office365.com/SMTP.Send%20offline_access"
            auth_url += "&response_mode=query"
            auth_url += f"&state={state_encoded}"
            auth_url += f"&login_hint={email}"
            auth_url += "&domain_hint=organizations"
            
        elif 'gmail.com' in domain:
            # Google OAuth URL
            client_id = os.environ.get('GOOGLE_CLIENT_ID')
            if not client_id:
                return jsonify({
                    "error": "Google OAuth not configured. Please set GOOGLE_CLIENT_ID in environment variables."
                }), 500
            
            # Store email in session for OAuth callback
            session['oauth_email'] = email
            
            # Create state parameter with expected email
            state_data = {
                "expected_email": email,
                "nonce": secrets.token_urlsafe(16)
            }
            state_json = json.dumps(state_data)
            # URL-encode the state to avoid odd characters
            import urllib.parse
            state_encoded = urllib.parse.quote(state_json)
            
            auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
            auth_url += f"?client_id={client_id}"
            auth_url += "&response_type=code"
            auth_url += "&redirect_uri=http://localhost:5000/api/auth/google/callback"
            auth_url += "&scope=https://mail.google.com/ openid email profile"
            auth_url += f"&state={state_encoded}"
            auth_url += "&access_type=offline"
            auth_url += "&prompt=consent"
            
        else:
            return jsonify({
                "error": "OAuth not supported for this email provider yet"
            }), 400
        
        # Determine provider based on domain
        provider = "google" if 'gmail.com' in domain else "microsoft"
        
        return jsonify({
            "success": True,
            "data": {
                "auth_url": auth_url,
                "provider": provider
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# --- Microsoft OAuth Callback ---
@email_accounts_bp.route("/auth/microsoft/callback", methods=["GET"])
def microsoft_oauth_callback():
    """Handle Microsoft OAuth callback and store tokens with identity validation"""
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
        # Decode expected email from state
        expected_email = None
        if state:
            try:
                # URL-decode the state first, then try JSON parsing
                import urllib.parse
                state_decoded = urllib.parse.unquote(state)
                state_data = json.loads(state_decoded)
                expected_email = state_data.get('expected_email')
            except json.JSONDecodeError:
                # Fallback to base64 encoding
                expected_email = base64.b64decode(state.encode()).decode()
        
        if not expected_email:
            expected_email = session.get('oauth_email')
        
        print(f"Expected email from OAuth: {expected_email}")
        
        # Exchange code for tokens
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
        
        # Get Graph token to fetch user identity
        graph_token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'scope': 'https://graph.microsoft.com/.default offline_access'
        }
        
        graph_response = requests.post(token_url, data=graph_token_data)
        if graph_response.status_code == 200:
            graph_token = graph_response.json().get('access_token')
            
            # Fetch user identity from Graph API
            me_response = requests.get(
                "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName,proxyAddresses",
                headers={"Authorization": f"Bearer {graph_token}"},
                timeout=10
            )
            
            if me_response.status_code == 200:
                me_data = me_response.json()
                upn = (me_data.get("userPrincipalName") or "").lower()
                mail = (me_data.get("mail") or "").lower()
                proxy_addresses = [p.lower() for p in me_data.get("proxyAddresses", [])]
                
                # Find primary SMTP address
                primary_proxy = None
                for proxy in proxy_addresses:
                    if proxy.startswith("smtp:"):
                        primary_proxy = proxy.split(":", 1)[1]
                        break
                
                # Determine canonical email (the actual mailbox owner)
                canonical_email = mail or primary_proxy or upn
                
                print(f"Graph API user data:")
                print(f"  UPN: {upn}")
                print(f"  Mail: {mail}")
                print(f"  Primary Proxy: {primary_proxy}")
                print(f"  Canonical Email: {canonical_email}")
                print(f"  Expected Email: {expected_email}")
                
                # Check if expected email matches any of the user's addresses
                user_addresses = {canonical_email, upn, mail}
                if primary_proxy:
                    user_addresses.add(primary_proxy)
                
                # Add all proxy addresses
                for proxy in proxy_addresses:
                    if ":" in proxy:
                        user_addresses.add(proxy.split(":", 1)[1])
                
                expected_email_lower = expected_email.lower() if expected_email else ""
                
                if expected_email and expected_email_lower not in user_addresses:
                    # Identity mismatch - user signed in as different account
                    error_msg = f"You signed in as {canonical_email} but tried to connect {expected_email}. Please sign in as {expected_email}."
                    print(f"Identity mismatch: {error_msg}")
                    return redirect(f"http://localhost:3000/oauth-callback?success=false&error={error_msg}&provider=microsoft")
                
                # Use canonical email for storage (the actual mailbox owner)
                storage_email = canonical_email
                print(f"Using canonical email for storage: {storage_email}")
            else:
                print(f"Failed to fetch user identity from Graph API: {me_response.status_code}")
                # Fallback to expected email if Graph API fails
                storage_email = expected_email
        else:
            print(f"Failed to get Graph token: {graph_response.status_code}")
            # Fallback to expected email if Graph token fails
            storage_email = expected_email
        
        # Calculate expiry time
        expiry_time = datetime.now() + timedelta(seconds=expires_in)
        
        # Store tokens in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID from session or create a placeholder
        user_id = session.get('user_id')
        if not user_id:
            # Try to get user ID from email
            cursor.execute("SELECT id FROM users WHERE email = %s", (expected_email,))
            user_result = cursor.fetchone()
            user_id = user_result[0] if user_result else None
        
        if user_id:
            # Delete any existing account for this user to ensure fresh tokens
            cursor.execute("""
                DELETE FROM user_email_accounts 
                WHERE user_id = %s
            """, (user_id,))
            
            # Insert new user email account with canonical email
            cursor.execute("""
                INSERT INTO user_email_accounts 
                (user_id, email_address, provider_type, access_token, refresh_token, token_expiry, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, storage_email, 'microsoft', access_token, refresh_token, expiry_time, True))
            
            conn.commit()
            print(f"Stored OAuth tokens for user {user_id}, canonical email {storage_email}")
        
        cursor.close()
        conn.close()
        
        # Clear session data
        session.pop('oauth_email', None)
        
        return redirect(f"http://localhost:3000/oauth-callback?success=true&provider=microsoft&email={storage_email}")
        
    except Exception as e:
        print(f"Error processing OAuth callback: {e}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=processing_error")

# --- Google OAuth Callback ---
@email_accounts_bp.route("/auth/google/callback", methods=["GET"])
def google_oauth_callback():
    """Handle Google OAuth callback and store tokens"""
    code = request.args.get('code')
    error = request.args.get('error')
    state = request.args.get('state')
    
    print(f"Google OAuth Callback - Code: {code}, Error: {error}, State: {state}")
    
    if error:
        print(f"Google OAuth Error: {error}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=" + error)
    
    if not code:
        return redirect("http://localhost:3000/oauth-callback?success=false&error=no_code")
    
    try:
        # Decode expected email from state
        expected_email = None
        if state:
            try:
                # URL-decode the state first, then try JSON parsing
                import urllib.parse
                state_decoded = urllib.parse.unquote(state)
                state_data = json.loads(state_decoded)
                expected_email = state_data.get("expected_email")
            except (json.JSONDecodeError, TypeError):
                # Fallback to base64 decoding
                try:
                    expected_email = base64.b64decode(state.encode()).decode()
                except:
                    expected_email = None
        
        if not expected_email:
            expected_email = session.get('oauth_email')
        
        if not expected_email:
            return redirect("http://localhost:3000/oauth-callback?success=false&error=no_email")
        
        # Exchange code for tokens
        client_id = os.environ.get('GOOGLE_CLIENT_ID')
        client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
        
        if not client_id or not client_secret:
            return redirect("http://localhost:3000/oauth-callback?success=false&error=oauth_not_configured")
        
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:5000/api/auth/google/callback'
        }
        
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data=token_data,
            timeout=10
        )
        
        if token_response.status_code != 200:
            print(f"Google token exchange failed: {token_response.status_code} - {token_response.text}")
            return redirect("http://localhost:3000/oauth-callback?success=false&error=token_exchange_failed")
        
        token_response_data = token_response.json()
        access_token = token_response_data.get('access_token')
        refresh_token = token_response_data.get('refresh_token')
        expires_in = token_response_data.get('expires_in', 3600)
        
        # Calculate expiry time
        expiry_time = datetime.now() + timedelta(seconds=expires_in)
        
        # Store tokens in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID from session or create a placeholder
        user_id = session.get('user_id')
        if not user_id:
            # Try to get user ID from email
            cursor.execute("SELECT id FROM users WHERE email = %s", (expected_email,))
            user_result = cursor.fetchone()
            user_id = user_result[0] if user_result else None
        
        if user_id:
            # Delete any existing account for this user to ensure fresh tokens
            cursor.execute("""
                DELETE FROM user_email_accounts 
                WHERE user_id = %s
            """, (user_id,))
            
            # Insert new user email account
            cursor.execute("""
                INSERT INTO user_email_accounts 
                (user_id, email_address, provider_type, access_token, refresh_token, token_expiry, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, expected_email, 'google', access_token, refresh_token, expiry_time, True))
            
            conn.commit()
            print(f"Stored Google OAuth tokens for user {user_id}, email {expected_email}")
        
        cursor.close()
        conn.close()
        
        # Clear session data
        session.pop('oauth_email', None)
        
        return redirect(f"http://localhost:3000/oauth-callback?success=true&provider=google&email={expected_email}")
        
    except Exception as e:
        print(f"Error processing Google OAuth callback: {e}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=processing_error")

# --- Store Email Account ---
@email_accounts_bp.route("/email-accounts/store", methods=["POST"])
@require_auth
def store_email_account():
    """Store email account information"""
    try:
        user_email = get_current_user_email()
        data = request.json
        
        # For now, just return success
        # In a real implementation, you'd store this in your database
        return jsonify({
            "success": True,
            "message": "Email account stored successfully"
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# --- Get All User Email Accounts ---
@email_accounts_bp.route("/email-accounts", methods=["GET"])
@require_auth
def get_user_email_accounts():
    """Get all email accounts for the current user"""
    try:
        user_id = get_current_user_id()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, email_address, provider_type, is_active, created_at, last_synced_at
            FROM user_email_accounts 
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        
        accounts = []
        for row in cursor.fetchone():
            accounts.append({
                "id": row[0],
                "email_address": row[1],
                "provider_type": row[2],
                "is_active": row[3],
                "created_at": row[4].isoformat() if row[4] else None,
                "last_synced_at": row[5].isoformat() if row[5] else None
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "data": accounts
        }), 200
        
    except Exception as e:
        print(f"Error getting user email accounts: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# --- Disconnect Email Account ---
@email_accounts_bp.route("/email-accounts/disconnect", methods=["POST"])
@require_auth
def disconnect_email_account():
    """Disconnect email account"""
    try:
        user_id = get_current_user_id()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Deactivate all email accounts for this user
        cursor.execute("""
            UPDATE user_email_accounts 
            SET is_active = false, updated_at = NOW()
            WHERE user_id = %s
        """, (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Email account disconnected successfully"
        }), 200
        
    except Exception as e:
        print(f"Error disconnecting email account: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# --- Refresh Access Token ---
@email_accounts_bp.route("/email-accounts/refresh-token", methods=["POST"])
@require_auth
def refresh_access_token():
    """Refresh access token for a user's email account"""
    try:
        user_id = get_current_user_id()
        data = request.json
        email_address = data.get('email_address')
        
        if not email_address:
            return jsonify({"error": "Email address is required"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get current refresh token
        cursor.execute("""
            SELECT refresh_token FROM user_email_accounts 
            WHERE user_id = %s AND email_address = %s AND is_active = true
        """, (user_id, email_address))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Email account not found or not active"}), 404
        
        refresh_token = result[0]
        
        # Exchange refresh token for new access token
        client_id = os.environ.get('MICROSOFT_CLIENT_ID')
        client_secret = os.environ.get('MICROSOFT_CLIENT_SECRET')
        tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID')
        
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        response = requests.post(token_url, data=token_data)
        
        if response.status_code != 200:
            return jsonify({"error": "Failed to refresh token"}), 400
        
        token_response = response.json()
        new_access_token = token_response.get('access_token')
        new_refresh_token = token_response.get('refresh_token', refresh_token)
        expires_in = token_response.get('expires_in', 3600)
        
        # Update tokens in database
        expiry_time = datetime.now() + timedelta(seconds=expires_in)
        
        cursor.execute("""
            UPDATE user_email_accounts 
            SET access_token = %s, refresh_token = %s, token_expiry = %s, updated_at = NOW()
            WHERE user_id = %s AND email_address = %s
        """, (new_access_token, new_refresh_token, expiry_time, user_id, email_address))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Token refreshed successfully"
        }), 200
        
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
