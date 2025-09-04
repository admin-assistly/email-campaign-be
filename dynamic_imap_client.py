#!/usr/bin/env python3
"""
Dynamic IMAP Client Factory
Handles any email provider with appropriate authentication methods
"""

import imaplib
import ssl
import socket
import os
import requests
import base64
import json
from typing import Dict, Optional, Tuple
from email_provider_config import EmailProviderConfig
import logging

logger = logging.getLogger(__name__)

class DynamicIMAPClient:
    """Dynamic IMAP client that adapts to any email provider"""
    
    def __init__(self, email_address: str, provider_config: Dict):
        self.email_address = email_address
        self.provider_config = provider_config
        self.mail = None
        self.connected = False
    
    def connect(self, auth_credentials: Dict) -> bool:
        """Connect to IMAP server with appropriate authentication"""
        try:
            # Get IMAP configuration
            imap_server = self.provider_config['imap_server']
            imap_port = self.provider_config['imap_port']
            imap_ssl = self.provider_config['imap_ssl']
            
            logger.info(f"Connecting to {imap_server}:{imap_port} for {self.email_address}")
            
            # Create SSL context if needed
            ssl_context = None
            if imap_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Connect to IMAP server
            if imap_ssl:
                self.mail = imaplib.IMAP4_SSL(imap_server, imap_port, ssl_context=ssl_context)
            else:
                self.mail = imaplib.IMAP4(imap_server, imap_port)
                if self.provider_config.get('imap_starttls'):
                    self.mail.starttls()
            
            # Authenticate using appropriate method
            auth_method = auth_credentials.get('auth_method', 'oauth2')
            
            if auth_method == 'oauth2':
                success = self._authenticate_oauth2(auth_credentials)
            elif auth_method == 'app_password':
                success = self._authenticate_app_password(auth_credentials)
            elif auth_method == 'basic_auth':
                success = self._authenticate_basic(auth_credentials)
            else:
                logger.error(f"Unsupported authentication method: {auth_method}")
                return False
            
            if success:
                self.connected = True
                logger.info(f"Successfully connected to {self.provider_config['name']}")
                return True
            else:
                logger.error(f"Authentication failed for {self.email_address}")
                return False
                
        except Exception as e:
            logger.error(f"Connection failed for {self.email_address}: {e}")
            return False
    
    def _authenticate_oauth2(self, auth_credentials: Dict) -> bool:
        """Authenticate using OAuth2"""
        try:
            access_token = auth_credentials.get('access_token')
            if not access_token:
                logger.error("No access token provided for OAuth2 authentication")
                return False
            
            oauth_provider = self.provider_config.get('oauth_provider')
            
            if oauth_provider == 'google':
                return self._authenticate_gmail_oauth2(access_token)
            elif oauth_provider == 'microsoft':
                return self._authenticate_microsoft_oauth2(access_token)
            elif oauth_provider == 'yahoo':
                return self._authenticate_yahoo_oauth2(access_token)
            else:
                logger.error(f"OAuth2 not supported for provider: {oauth_provider}")
                return False
                
        except Exception as e:
            logger.error(f"OAuth2 authentication failed: {e}")
            return False
    
    def _authenticate_gmail_oauth2(self, access_token: str) -> bool:
        """Authenticate to Gmail using OAuth2"""
        try:
            auth_string = f'user={self.email_address}\1auth=Bearer {access_token}\1\1'
            self.mail.authenticate('XOAUTH2', lambda x: auth_string)
            return True
        except Exception as e:
            logger.error(f"Gmail OAuth2 authentication failed: {e}")
            return False
    
    def _decode_jwt_noverify(self, token):
        """Decode JWT token without verification"""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload_b64 = parts[1] + "=="
            return json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            logger.debug(f"JWT decode failed: {e}")
            return {}
    
    def _pick_principal_for_imap(self, access_token, account_email):
        """Pick the correct principal for IMAP authentication"""
        payload = self._decode_jwt_noverify(access_token)
        principal = payload.get("preferred_username") or payload.get("upn") or account_email
        aud = payload.get("aud")
        scp = payload.get("scp", "")
        logger.info(f"Connecting to IMAP for {account_email} - aud={aud} scp={scp}")
        if principal.lower() != account_email.lower():
            logger.warning(f"Using UPN for Microsoft OAuth2: {principal} (original: {account_email})")
        return principal
    
    def _authenticate_microsoft_oauth2(self, access_token: str) -> bool:
        """Authenticate to Microsoft using OAuth2"""
        try:
            import base64
            import json
            
            # Always use the token's principal for authentication
            login_id = self._pick_principal_for_imap(access_token, self.email_address)
            
            # Build XOAUTH2 string with the correct principal
            auth_string = f'user={login_id}\1auth=Bearer {access_token}\1\1'
            
            self.mail.authenticate('XOAUTH2', lambda x: auth_string)
            return True
        except Exception as e:
            logger.error(f"Microsoft OAuth2 authentication failed: {e}")
            return False
    
    def _authenticate_yahoo_oauth2(self, access_token: str) -> bool:
        """Authenticate to Yahoo using OAuth2"""
        try:
            auth_string = f'user={self.email_address}\1auth=Bearer {access_token}\1\1'
            self.mail.authenticate('XOAUTH2', lambda x: auth_string)
            return True
        except Exception as e:
            logger.error(f"Yahoo OAuth2 authentication failed: {e}")
            return False
    
    def _authenticate_app_password(self, auth_credentials: Dict) -> bool:
        """Authenticate using app password"""
        try:
            username = auth_credentials.get('username', self.email_address)
            password = auth_credentials.get('password')
            
            if not password:
                logger.error("No app password provided")
                return False
            
            self.mail.login(username, password)
            return True
            
        except Exception as e:
            logger.error(f"App password authentication failed: {e}")
            return False
    
    def _authenticate_basic(self, auth_credentials: Dict) -> bool:
        """Authenticate using basic username/password"""
        try:
            username = auth_credentials.get('username', self.email_address)
            password = auth_credentials.get('password')
            
            if not password:
                logger.error("No password provided for basic authentication")
                return False
            
            self.mail.login(username, password)
            return True
            
        except Exception as e:
            logger.error(f"Basic authentication failed: {e}")
            return False
    
    def list_mailboxes(self) -> Tuple[bool, list]:
        """List available mailboxes"""
        if not self.connected:
            return False, []
        
        try:
            status, mailboxes = self.mail.list()
            if status == 'OK':
                return True, mailboxes
            else:
                logger.error(f"Failed to list mailboxes: {mailboxes}")
                return False, []
        except Exception as e:
            logger.error(f"Error listing mailboxes: {e}")
            return False, []
    
    def select_mailbox(self, mailbox_name: str) -> bool:
        """Select a mailbox"""
        if not self.connected:
            return False
        
        try:
            sel = f'"{mailbox_name}"' if ' ' in mailbox_name else mailbox_name
            status, _ = self.mail.select(sel)
            if status == 'OK':
                logger.info(f"Selected mailbox: {mailbox_name}")
                return True
            else:
                logger.error(f"Failed to select mailbox {mailbox_name}")
                return False
        except Exception as e:
            logger.error(f"Error selecting mailbox {mailbox_name}: {e}")
            return False
    
    def search_messages(self, search_criteria: str) -> Tuple[bool, list]:
        """Search for messages"""
        if not self.connected:
            return False, []
        
        try:
            status, data = self.mail.search(None, search_criteria)
            if status == 'OK':
                message_ids = data[0].split()
                return True, message_ids
            else:
                logger.error(f"Search failed: {data}")
                return False, []
        except Exception as e:
            logger.error(f"Error searching messages: {e}")
            return False, []
    
    def fetch_message(self, message_id: bytes) -> Tuple[bool, Optional[bytes]]:
        """Fetch a message by ID"""
        if not self.connected:
            return False, None
        
        try:
            status, msg_data = self.mail.fetch(message_id, '(RFC822)')
            if status == 'OK':
                return True, msg_data[0][1]
            else:
                logger.error(f"Failed to fetch message {message_id}: {msg_data}")
                return False, None
        except Exception as e:
            logger.error(f"Error fetching message {message_id}: {e}")
            return False, None
    
    def mark_as_read(self, message_id: bytes) -> bool:
        """Mark a message as read"""
        if not self.connected:
            return False
        
        try:
            status, _ = self.mail.store(message_id, '+FLAGS', '\\Seen')
            return status == 'OK'
        except Exception as e:
            logger.error(f"Error marking message as read: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.mail and self.connected:
            try:
                self.mail.logout()
                self.connected = False
                logger.info(f"Disconnected from {self.provider_config['name']}")
            except Exception as e:
                logger.error(f"Error during logout: {e}")

class IMAPClientFactory:
    """Factory for creating IMAP clients for any provider"""
    
    @staticmethod
    def create_client(email_address: str) -> DynamicIMAPClient:
        """Create an IMAP client for the given email address"""
        provider_config = EmailProviderConfig.detect_provider(email_address)
        
        # Validate configuration
        is_valid, error_msg = EmailProviderConfig.validate_config(provider_config)
        if not is_valid:
            raise ValueError(f"Invalid provider configuration: {error_msg}")
        
        return DynamicIMAPClient(email_address, provider_config)
    
    @staticmethod
    def get_supported_providers() -> list:
        """Get list of supported email providers"""
        return list(EmailProviderConfig.PROVIDER_CONFIGS.keys())
    
    @staticmethod
    def test_connection(email_address: str, auth_credentials: Dict) -> Tuple[bool, str]:
        """Test connection to an email account"""
        try:
            client = IMAPClientFactory.create_client(email_address)
            
            if client.connect(auth_credentials):
                success, mailboxes = client.list_mailboxes()
                client.disconnect()
                
                if success:
                    return True, f"Connection successful. Found {len(mailboxes)} mailboxes."
                else:
                    return False, "Connected but failed to list mailboxes."
            else:
                return False, "Failed to connect to IMAP server."
                
        except Exception as e:
            return False, f"Connection test failed: {e}"
