#!/usr/bin/env python3
"""
Dynamic Multi-User IMAP Fetcher
Handles multiple users' email accounts with individual OAuth tokens
"""

import os
import time
import imaplib
import email
import requests
import re
import base64
import json
from datetime import datetime, timedelta, timezone
from msal import ConfidentialClientApplication
from dotenv import load_dotenv
from email_cleaner import clean_email_content
from db.postgres import get_db_connection
import threading
import logging

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('imap_fetcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_BASE_URL = os.environ.get('API_URL', 'http://127.0.0.1:5000/api')
RESPONSES_API_URL = f"{API_BASE_URL}/responses"
EMAILS_API_URL = f"{API_BASE_URL}/emails"
POLL_INTERVAL = int(os.environ.get('IMAP_POLL_INTERVAL', 30))  # Increased for multi-user
SENT_LOOKBACK_DAYS = int(os.environ.get('SENT_LOOKBACK_DAYS', 7))

class DynamicIMAPFetcher:
    """Dynamic IMAP fetcher for multiple user email accounts"""
    
    def __init__(self):
        self.running = False
        self.threads = {}
        self.lock = threading.Lock()
    
    def peek_jwt(self, jwt):
        """Inspect JWT token to check audience and scopes"""
        try:
            hdr, payload, *_ = jwt.split(".")
            payload = json.loads(base64.urlsafe_b64decode(payload + "=="))
            return {k: payload.get(k) for k in ("aud","scp","tid","upn","preferred_username","exp")}
        except Exception as e:
            logger.error(f"Error decoding JWT: {e}")
            return {}
        
    def get_active_user_accounts(self):
        """Get all active user email accounts from database"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    uea.id,
                    uea.user_id,
                    uea.email_address,
                    uea.provider_type,
                    uea.access_token,
                    uea.refresh_token,
                    uea.token_expiry,
                    uea.is_active,
                    u.email as user_email
                FROM user_email_accounts uea
                JOIN users u ON uea.user_id = u.id
                WHERE uea.is_active = true 
                ORDER BY uea.last_synced_at ASC NULLS FIRST
            """)
            
            accounts = []
            for row in cursor.fetchall():
                accounts.append({
                    'id': row[0],
                    'user_id': row[1],
                    'email_address': row[2],
                    'provider_type': row[3],
                    'access_token': row[4],
                    'refresh_token': row[5],
                    'token_expiry': row[6],
                    'is_active': row[7],
                    'user_email': row[8]
                })
            
            cursor.close()
            conn.close()
            
            logger.info(f"Found {len(accounts)} active user email accounts")
            return accounts
            
        except Exception as e:
            logger.error(f"Error getting active user accounts: {e}")
            return []
    
    def _safe_is_jwt(self, tok: str) -> bool:
        # Google access tokens are often opaque (not JWT) — avoid decoding noise
        return tok.count(".") == 2

    def refresh_token_if_needed(self, account):
        """Refresh access token if it's expired or about to expire."""
        try:
            if not account.get('token_expiry'):
                logger.warning(f"No token_expiry stored for {account['email_address']}")
                return False

            # Postgres may return naive timestamp; normalize to aware UTC
            exp = account['token_expiry']
            if getattr(exp, "tzinfo", None) is None:
                exp = exp.replace(tzinfo=timezone.utc)

            # Refresh if < 2 minutes left
            if exp > datetime.now(timezone.utc) + timedelta(minutes=2):
                return True

            logger.info(f"Refreshing token for {account['email_address']} ({account['provider_type']})")

            provider = (account.get('provider_type') or '').lower()
            refresh_token = account.get('refresh_token')
            if not refresh_token:
                logger.error(f"No refresh_token stored for {account['email_address']}")
                return False

            if provider == 'google':
                token_url = "https://oauth2.googleapis.com/token"
                payload = {
                    "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
                    "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                }
            elif provider == 'microsoft':
                tenant_id = os.environ.get('MICROSOFT_TENANT_ID') or os.environ.get('TENANT_ID', 'common')
                token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
                payload = {
                    "client_id": os.environ.get("MICROSOFT_CLIENT_ID"),
                    "client_secret": os.environ.get("MICROSOFT_CLIENT_SECRET"),
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                }
            else:
                logger.error(f"Unsupported provider '{provider}' for {account['email_address']}")
                return False

            resp = requests.post(token_url, data=payload, timeout=15)
            if resp.status_code != 200:
                logger.error(f"Token refresh failed for {account['email_address']} [{provider}]: "
                             f"{resp.status_code} {resp.text}")
                return False

            tr = resp.json()
            new_access = tr.get("access_token")
            new_refresh = tr.get("refresh_token") or refresh_token  # Google often omits on refresh
            expires_in = int(tr.get("expires_in", 3600))
            new_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            # Persist
            conn = get_db_connection(); cur = conn.cursor()
            cur.execute("""
                UPDATE user_email_accounts
                   SET access_token=%s, refresh_token=%s, token_expiry=%s, updated_at=NOW()
                 WHERE id=%s
            """, (new_access, new_refresh, new_expiry, account['id']))
            conn.commit(); cur.close(); conn.close()

            # Update in-memory
            account['access_token'] = new_access
            account['refresh_token'] = new_refresh
            account['token_expiry'] = new_expiry

            # Only try to peek if it looks like a JWT
            if new_access and self._safe_is_jwt(new_access):
                token_info = self.peek_jwt(new_access)
                logger.info(f"Token for {account['email_address']} - aud={token_info.get('aud')} scp={token_info.get('scp')}")
            else:
                logger.info(f"Token for {account['email_address']} refreshed (opaque token)")

            return True

        except Exception as e:
            logger.error(f"Error refreshing token for {account['email_address']}: {e}")
            return False
    
    def get_known_subscribers(self):
        """Get known subscribers from the database"""
        try:
            r = requests.get(EMAILS_API_URL, timeout=5)
            if r.ok:
                return {e['recipient_email'].strip().lower() for e in r.json()}
            return set()
        except Exception as e:
            logger.error(f"Error getting known subscribers: {e}")
            return set()
    
    def is_duplicate(self, mid):
        """Check if message is duplicate"""
        if not mid:
            return False
            
        try:
            clean_mid = mid.strip().strip('<>')
            
            variations = [clean_mid, f"<{clean_mid}>", mid]
            
            for variation in variations:
                r = requests.get(
                    f"{RESPONSES_API_URL}/by-message-id?message_id={variation}",
                    timeout=5
                )
                
                if r.ok:
                    responses = r.json()
                    if responses and len(responses) > 0:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking duplicates: {e}")
            return False
    
    def is_campaign(self, mid):
        """Check if message is a campaign email"""
        try:
            r = requests.get(f"{EMAILS_API_URL}?message_id={mid}", timeout=5)
            if not r.ok:
                return False
            data = r.json()
            if isinstance(data, list):
                return any(e.get('message_id') == mid for e in data)
            return data.get('message_id') == mid
        except Exception as e:
            logger.error(f"Error checking if campaign: {e}")
            return False
    
    def extract_body(self, msg):
        """Extract and clean email body"""
        raw_html = None
        raw_text = None
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get('Content-Disposition', '')
                
                if 'attachment' in content_disposition.lower():
                    continue
                    
                if content_type == 'text/html' and not raw_html:
                    raw_html = part.get_payload(decode=True).decode(errors='ignore')
                elif content_type == 'text/plain' and not raw_text:
                    raw_text = part.get_payload(decode=True).decode(errors='ignore')
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                raw_html = msg.get_payload(decode=True).decode(errors='ignore')
            else:
                raw_text = msg.get_payload(decode=True).decode(errors='ignore')
        
        cleaned_text, quoted_removed = clean_email_content(raw_html=raw_html, raw_text=raw_text)
        
        if quoted_removed:
            logger.debug(f"Quoted content removed from email")
        
        return cleaned_text
    
    def find_parent_response(self, in_reply_to, references):
        """Find parent response for threading"""
        if not in_reply_to:
            return None, None
        
        try:
            clean_mid = in_reply_to.strip().strip('<>')
            
            # Try to find in responses
            r = requests.get(f"{RESPONSES_API_URL}/by-message-id?message_id={clean_mid}", timeout=5)
            if r.ok:
                responses = r.json()
                if responses and len(responses) > 0:
                    parent_response = responses[0]
                    return parent_response['email_id'], parent_response['id']
            
            # Try with angle brackets
            r = requests.get(f"{RESPONSES_API_URL}/by-message-id?message_id=<{clean_mid}>", timeout=5)
            if r.ok:
                responses = r.json()
                if responses and len(responses) > 0:
                    parent_response = responses[0]
                    return parent_response['email_id'], parent_response['id']
            
            # Try to find in emails (original campaign email)
            r = requests.get(f"{EMAILS_API_URL}?message_id={clean_mid}", timeout=5)
            if r.ok:
                emails = r.json()
                if emails and len(emails) > 0:
                    original_email = emails[0]
                    return original_email['id'], None
            
            return None, None
            
        except Exception as e:
            logger.error(f"Error finding parent response: {e}")
            return None, None
    
    def trigger_classification(self, response_id):
        """Trigger classification for a response"""
        try:
            classification_url = f"{API_BASE_URL}/responses/{response_id}/classify"
            classification_response = requests.post(classification_url, timeout=30)
            
            if classification_response.ok:
                result = classification_response.json()
                logger.info(f"Classification triggered for response {response_id}")
                return True
            else:
                logger.error(f"Classification failed for response {response_id}: {classification_response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Classification trigger failed: {e}")
            return False
    
    def process_message(self, msg, subs, folder, account):
        """Process a single email message"""
        try:
            mid = msg.get('Message-ID')
            if not mid:
                logger.debug("Skipping message with no Message-ID")
                return False

            logger.debug(f"Processing message: {mid}")
            
            if self.is_duplicate(mid):
                logger.debug(f"Duplicate message_id detected: {mid}")
                return False

            if self.is_campaign(mid):
                logger.debug(f"Skipping campaign-origin message: {mid}")
                return False

            frm = email.utils.parseaddr(msg.get('From',''))[1].lower()
            to_ = email.utils.parseaddr(msg.get('To',''))[1].lower()
            
            # INBOX rule
            if folder == 'inbox':
                if subs and frm not in subs:
                    logger.debug(f"Skipping INBOX from {frm}: not in subscribers")
                    return False

            # SENT rule
            if folder == 'sent':
                if frm != account['email_address'].lower():
                    logger.debug(f"Skipping SENT from {frm}: not from connected account")
                    return False
                if subs and to_ not in subs:
                    logger.debug(f"Skipping SENT to {to_}: not in subscribers")
                    return False

            # Extract threading headers
            in_reply_to = msg.get('In-Reply-To')
            references = msg.get('References')
            
            # Find parent response for proper threading
            email_id, parent_response_id = self.find_parent_response(in_reply_to, references)
            
            # Extract and clean the email body
            raw_body = self.extract_body(msg)
            
            payload = {
                "email_id": email_id,
                "parent_response_id": parent_response_id,
                "responder_email": frm,
                "body": raw_body,
                "message_id": mid,
                "in_reply_to": in_reply_to,
                "references_chain": references,
                "subject": msg.get('Subject',''),
                "from_imap": True,
                "recipient_email": to_,
            }

            logger.debug(f"Creating response for message: {mid}")

            r = requests.post(RESPONSES_API_URL, json=payload, timeout=10)
            
            if r.ok:
                response_data = r.json()
                response_id = response_data.get('id')
                is_duplicate_response = response_data.get('duplicate', False)
                
                if is_duplicate_response:
                    logger.debug(f"Duplicate response detected for ID: {response_id}")
                    return True
                
                logger.info(f"Response created with ID: {response_id}")

                if response_id:
                    self.trigger_classification(response_id)
                return True

            logger.error(f"Failed to create response: {r.status_code} - {r.text}")
            return False
            
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return False
    
    def process_mailbox(self, account, mailbox_name, subs, folder, since=None):
        """Process a mailbox for a specific user account"""
        mail = None
        try:
            # Refresh token if needed
            if not self.refresh_token_if_needed(account):
                logger.error(f"Failed to refresh token for {account['email_address']}")
                return
            
            # Use dynamic IMAP client
            from dynamic_imap_client import IMAPClientFactory
            
            try:
                # Create dynamic IMAP client
                client = IMAPClientFactory.create_client(account['email_address'])
                
                # Log token details before authentication (only if it's a JWT)
                if self._safe_is_jwt(account['access_token']):
                    token_info = self.peek_jwt(account['access_token'])
                    logger.info(f"Connecting to IMAP for {account['email_address']} - aud={token_info.get('aud')} scp={token_info.get('scp')}")
                else:
                    logger.info(f"Connecting to IMAP for {account['email_address']} - opaque token")
                
                # Prepare auth credentials
                auth_credentials = {
                    'auth_method': 'oauth2',
                    'access_token': account['access_token']
                }
                
                # Connect using dynamic client
                if not client.connect(auth_credentials):
                    logger.error(f"Failed to connect to IMAP for {account['email_address']}")
                    return
                
                # Use the dynamic client for all operations
                mail = client.mail
                logger.debug(f"Successfully authenticated to IMAP for {account['email_address']}")
                
                # Verify connection with capability and noop
                try:
                    typ, caps = mail.capability()
                    logger.debug(f"IMAP capabilities: {caps}")
                    mail.noop()
                except Exception as e:
                    logger.warning(f"Capability/noop check failed: {e}")
                
            except Exception as e:
                logger.error(f"Error creating dynamic IMAP client for {account['email_address']}: {e}")
                return
            
            # Select mailbox with retry logic
            sel = f'"{mailbox_name}"' if ' ' in mailbox_name else mailbox_name
            logger.info(f"Attempting to SELECT mailbox: {sel}")
            
            for attempt in range(2):
                try:
                    status, data = mail.select(sel)
                    if status == 'OK':
                        logger.info(f"Successfully selected mailbox: {sel}")
                        break
                    else:
                        logger.error(f"SELECT failed on attempt {attempt + 1}: {status} - {data}")
                        if attempt == 0:
                            time.sleep(0.5)  # Brief delay before retry
                            # Try capability and noop before retry
                            try:
                                mail.capability()
                                mail.noop()
                            except Exception as e:
                                logger.debug(f"Capability/noop before retry failed: {e}")
                        else:
                            logger.error(f"Cannot open {sel!r} after retries")
                            return
                except Exception as e:
                    logger.error(f"SELECT command error on attempt {attempt + 1}: {e}")
                    if attempt == 0:
                        time.sleep(0.5)
                    else:
                        return

            # Search for messages
            if folder == 'inbox':
                search_str = "UNSEEN"
                if since:
                    search_str = f"({search_str} SINCE {since.strftime('%d-%b-%Y')})"
                
                status, data = mail.search(None, search_str)
                if status == 'OK':
                    all_ids = data[0].split()
                    logger.info(f"Found {len(all_ids)} UNSEEN messages in {sel!r}")
                else:
                    logger.error(f"UNSEEN search failed in {sel!r}")
                    return
            else:
                search_str = "ALL"
                if since:
                    search_str = f"(SINCE {since.strftime('%d-%b-%Y')})"
                
                status, data = mail.search(None, search_str)
                if status != 'OK':
                    logger.error(f"Search failed in {sel!r}")
                    return
                
                all_ids = data[0].split()
                logger.info(f"Found {len(all_ids)} messages in {sel!r} (since {since.strftime('%Y-%m-%d')})")

            processed_count = 0
            for num in all_ids:
                try:
                    _, msg_data = mail.fetch(num, '(RFC822)')
                    msg = email.message_from_bytes(msg_data[0][1])
                    
                    if self.process_message(msg, subs, folder, account):
                        mail.store(num, '+FLAGS', '\\Seen')
                        processed_count += 1
                        
                except Exception as e:
                    logger.error(f"Error processing message {num}: {e}")
                    continue
            
            logger.info(f"Successfully processed {processed_count} messages from {sel!r}")
            
            # Update last_synced_at
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE user_email_accounts 
                SET last_synced_at = NOW() 
                WHERE id = %s
            """, (account['id'],))
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error processing mailbox for {account['email_address']}: {e}")
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception as logout_error:
                    logger.debug(f"Error during logout: {logout_error}")
    
    def process_user_account(self, account):
        """Process a single user's email account"""
        try:
            logger.info(f"Processing account: {account['email_address']}")
            
            # Get known subscribers
            subs = self.get_known_subscribers()
            
            # Process INBOX
            self.process_mailbox(account, 'INBOX', subs, 'inbox')
            
            # Process Sent Items (Gmail uses [Gmail]/Sent Mail)
            since = datetime.now(timezone.utc) - timedelta(days=SENT_LOOKBACK_DAYS)
            if account.get('provider_type', '').lower() == 'google':
                self.process_mailbox(account, '[Gmail]/Sent Mail', subs, 'sent', since)
            else:
                self.process_mailbox(account, 'Sent Items', subs, 'sent', since)
            
            logger.info(f"Completed processing for {account['email_address']}")
            
        except Exception as e:
            logger.error(f"Error processing user account {account['email_address']}: {e}")
    
    def start(self):
        """Start the dynamic IMAP fetcher"""
        self.running = True
        logger.info("Starting Dynamic IMAP Fetcher...")
        
        while self.running:
            try:
                # Get active user accounts
                accounts = self.get_active_user_accounts()
                
                if not accounts:
                    logger.info("No active user accounts found")
                    time.sleep(POLL_INTERVAL)
                    continue
                
                # Process each account
                for account in accounts:
                    try:
                        # Refresh token if needed
                        if not self.refresh_token_if_needed(account):
                            logger.warning(f"Skipping {account['email_address']} - token refresh failed")
                            continue
                        
                        self.process_user_account(account)
                    except Exception as e:
                        logger.error(f"Error processing account {account['email_address']}: {e}")
                
                logger.info(f"Completed polling cycle for {len(accounts)} accounts")
                
            except Exception as e:
                logger.error(f"Error in main polling loop: {e}")
            
            time.sleep(POLL_INTERVAL)
    
    def stop(self):
        """Stop the dynamic IMAP fetcher"""
        self.running = False
        logger.info("Stopping Dynamic IMAP Fetcher...")

def main():
    """Main function to run the dynamic IMAP fetcher"""
    fetcher = DynamicIMAPFetcher()
    
    try:
        fetcher.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
        fetcher.stop()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        fetcher.stop()

if __name__ == "__main__":
    main()
