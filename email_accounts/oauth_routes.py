#!/usr/bin/env python3
"""
Multi-Provider OAuth Routes
Supports Google, Microsoft, Yahoo, and other email providers
"""

import os
import base64
import requests
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, session, redirect, jsonify
from db.postgres import get_db_connection
from email_provider_config import EmailProviderConfig
import logging

logger = logging.getLogger(__name__)

oauth_bp = Blueprint('oauth', __name__)

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@oauth_bp.route("/auth/<provider>/url", methods=["POST"])
@require_auth
def get_oauth_url(provider):
    """Get OAuth URL for any supported provider"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Detect provider configuration
        provider_config = EmailProviderConfig.detect_provider(email)
        oauth_config = EmailProviderConfig.get_oauth_config(provider_config)
        
        if not oauth_config.get('auth_url'):
            return jsonify({'error': f'OAuth not supported for {provider_config["name"]}'}), 400
        
        # Store email in session for callback
        session['oauth_email'] = email
        session['oauth_provider'] = provider_config['oauth_provider']
        
        # Build OAuth URL based on provider
        auth_url = oauth_config['auth_url']
        
        if provider_config['oauth_provider'] == 'google':
            auth_url = _build_google_oauth_url(email, oauth_config, provider_config)
        elif provider_config['oauth_provider'] == 'microsoft':
            auth_url = _build_microsoft_oauth_url(email, oauth_config, provider_config)
        elif provider_config['oauth_provider'] == 'yahoo':
            auth_url = _build_yahoo_oauth_url(email, oauth_config, provider_config)
        else:
            return jsonify({'error': f'Unsupported OAuth provider: {provider_config["oauth_provider"]}'}), 400
        
        return jsonify({
            'auth_url': auth_url,
            'provider': provider_config['name'],
            'oauth_provider': provider_config['oauth_provider']
        })
        
    except Exception as e:
        logger.error(f"Error generating OAuth URL: {e}")
        return jsonify({'error': 'Failed to generate OAuth URL'}), 500

def _build_google_oauth_url(email, oauth_config, provider_config):
    """Build Google OAuth URL"""
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    if not client_id:
        raise ValueError("GOOGLE_CLIENT_ID environment variable not set")
    
    scopes = ' '.join(provider_config['oauth_scopes'])
    state = base64.b64encode(email.encode()).decode()
    
    auth_url = f"{oauth_config['auth_url']}?" + \
               f"client_id={client_id}&" + \
               f"redirect_uri={oauth_config['redirect_uri']}&" + \
               f"scope={scopes}&" + \
               f"response_type=code&" + \
               f"state={state}&" + \
               f"access_type=offline&" + \
               f"prompt=consent"
    
    return auth_url

def _build_microsoft_oauth_url(email, oauth_config, provider_config):
    """Build Microsoft OAuth URL"""
    client_id = os.environ.get('MICROSOFT_CLIENT_ID')
    tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID')
    
    if not client_id:
        raise ValueError("MICROSOFT_CLIENT_ID environment variable not set")
    if not tenant_id:
        raise ValueError("MICROSOFT_TENANT_ID environment variable not set")
    
    scopes = ' '.join(provider_config['oauth_scopes'])
    state = base64.b64encode(email.encode()).decode()
    
    auth_url = oauth_config['auth_url'].format(tenant_id=tenant_id) + "?" + \
               f"client_id={client_id}&" + \
               f"redirect_uri={oauth_config['redirect_uri']}&" + \
               f"scope={scopes}&" + \
               f"response_type=code&" + \
               f"state={state}&" + \
               f"response_mode=query"
    
    return auth_url

def _build_yahoo_oauth_url(email, oauth_config, provider_config):
    """Build Yahoo OAuth URL"""
    client_id = os.environ.get('YAHOO_CLIENT_ID')
    if not client_id:
        raise ValueError("YAHOO_CLIENT_ID environment variable not set")
    
    scopes = ' '.join(provider_config['oauth_scopes'])
    state = base64.b64encode(email.encode()).decode()
    
    auth_url = f"{oauth_config['auth_url']}?" + \
               f"client_id={client_id}&" + \
               f"redirect_uri={oauth_config['redirect_uri']}&" + \
               f"scope={scopes}&" + \
               f"response_type=code&" + \
               f"state={state}"
    
    return auth_url

@oauth_bp.route("/auth/<provider>/callback", methods=["GET"])
def oauth_callback(provider):
    """Handle OAuth callback for any provider"""
    code = request.args.get('code')
    error = request.args.get('error')
    state = request.args.get('state')
    
    logger.info(f"OAuth callback for {provider} - Code: {code}, Error: {error}")
    
    if error:
        logger.error(f"OAuth Error: {error}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=" + error)
    
    if not code:
        return redirect("http://localhost:3000/oauth-callback?success=false&error=no_code")
    
    try:
        # Decode email from state
        email = base64.b64decode(state.encode()).decode() if state else None
        if not email:
            email = session.get('oauth_email')
        
        if not email:
            return redirect("http://localhost:3000/oauth-callback?success=false&error=no_email")
        
        # Get provider configuration
        provider_config = EmailProviderConfig.detect_provider(email)
        oauth_config = EmailProviderConfig.get_oauth_config(provider_config)
        
        # Exchange code for tokens based on provider
        if provider_config['oauth_provider'] == 'google':
            tokens = _exchange_google_tokens(code, oauth_config)
        elif provider_config['oauth_provider'] == 'microsoft':
            tokens = _exchange_microsoft_tokens(code, oauth_config)
        elif provider_config['oauth_provider'] == 'yahoo':
            tokens = _exchange_yahoo_tokens(code, oauth_config)
        else:
            return redirect("http://localhost:3000/oauth-callback?success=false&error=unsupported_provider")
        
        if not tokens:
            return redirect("http://localhost:3000/oauth-callback?success=false&error=token_exchange_failed")
        
        # Store tokens in database
        _store_oauth_tokens(email, tokens, provider_config)
        
        # Clear session data
        session.pop('oauth_email', None)
        session.pop('oauth_provider', None)
        
        return redirect(f"http://localhost:3000/oauth-callback?success=true&provider={provider_config['oauth_provider']}&email={email}")
        
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {e}")
        return redirect("http://localhost:3000/oauth-callback?success=false&error=processing_error")

def _exchange_google_tokens(code, oauth_config):
    """Exchange authorization code for Google tokens"""
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_config['redirect_uri']
    }
    
    response = requests.post(oauth_config['token_url'], data=token_data, timeout=10)
    
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"Google token exchange failed: {response.status_code} - {response.text}")
        return None

def _exchange_microsoft_tokens(code, oauth_config):
    """Exchange authorization code for Microsoft tokens"""
    client_id = os.environ.get('MICROSOFT_CLIENT_ID')
    client_secret = os.environ.get('MICROSOFT_CLIENT_SECRET')
    tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID')
    
    token_url = oauth_config['token_url'].format(tenant_id=tenant_id)
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_config['redirect_uri']
    }
    
    response = requests.post(token_url, data=token_data, timeout=10)
    
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"Microsoft token exchange failed: {response.status_code} - {response.text}")
        return None

def _exchange_yahoo_tokens(code, oauth_config):
    """Exchange authorization code for Yahoo tokens"""
    client_id = os.environ.get('YAHOO_CLIENT_ID')
    client_secret = os.environ.get('YAHOO_CLIENT_SECRET')
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_config['redirect_uri']
    }
    
    response = requests.post(oauth_config['token_url'], data=token_data, timeout=10)
    
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"Yahoo token exchange failed: {response.status_code} - {response.text}")
        return None

def _store_oauth_tokens(email, tokens, provider_config):
    """Store OAuth tokens in database"""
    access_token = tokens.get('access_token')
    refresh_token = tokens.get('refresh_token')
    expires_in = tokens.get('expires_in', 3600)
    
    # Calculate expiry time
    expiry_time = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    
    # Get user ID from session
    user_id = session.get('user_id')
    if not user_id:
        # Try to get user ID from email
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_result = cursor.fetchone()
        user_id = user_result[0] if user_result else None
        cursor.close()
        conn.close()
    
    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete any existing account for this user/email
        cursor.execute("""
            DELETE FROM user_email_accounts 
            WHERE user_id = %s AND email_address = %s
        """, (user_id, email))
        
        # Insert new account with tokens
        cursor.execute("""
            INSERT INTO user_email_accounts 
            (user_id, email_address, provider_type, access_token, refresh_token, token_expiry, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, email, provider_config['oauth_provider'], access_token, refresh_token, expiry_time, True))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Stored OAuth tokens for user {user_id}, email {email}, provider {provider_config['oauth_provider']}")
    else:
        logger.error(f"Could not find user for email: {email}")

@oauth_bp.route("/auth/supported-providers", methods=["GET"])
def get_supported_providers():
    """Get list of supported email providers"""
    providers = EmailProviderConfig.PROVIDER_CONFIGS.keys()
    return jsonify({
        'providers': list(providers),
        'business_providers': list(EmailProviderConfig.BUSINESS_PROVIDERS.keys())
    })

@oauth_bp.route("/auth/test-connection", methods=["POST"])
@require_auth
def test_connection():
    """Test connection to an email account"""
    try:
        data = request.get_json()
        email = data.get('email')
        auth_method = data.get('auth_method', 'oauth2')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Get provider configuration
        provider_config = EmailProviderConfig.detect_provider(email)
        
        # Build auth credentials based on method
        auth_credentials = {'auth_method': auth_method}
        
        if auth_method == 'oauth2':
            # Get tokens from database
            user_id = session.get('user_id')
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT access_token FROM user_email_accounts 
                WHERE user_id = %s AND email_address = %s AND is_active = true
            """, (user_id, email))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result:
                auth_credentials['access_token'] = result[0]
            else:
                return jsonify({'error': 'No OAuth tokens found for this email'}), 400
        
        elif auth_method in ['app_password', 'basic_auth']:
            password = data.get('password')
            if not password:
                return jsonify({'error': 'Password is required for this authentication method'}), 400
            auth_credentials['password'] = password
        
        # Test connection
        from dynamic_imap_client import IMAPClientFactory
        success, message = IMAPClientFactory.test_connection(email, auth_credentials)
        
        return jsonify({
            'success': success,
            'message': message,
            'provider': provider_config['name']
        })
        
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        return jsonify({'error': 'Failed to test connection'}), 500
