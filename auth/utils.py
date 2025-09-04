# auth/utils.py
# Authentication helper functions
# Moved from original app.py: password hashing, email/password validation, SES verification

import bcrypt
import re
import json
from botocore.exceptions import ClientError

# --- Password Hashing ---
def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

# --- Email Validation ---
def validate_email_format(email: str) -> tuple[bool, str]:
    """
    Checks if the email string has a basic valid format and enforces lowercase.
    """
    email_regex_lowercase_enforced = r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-zA-Z]{2,4}$"

    if re.fullmatch(email_regex_lowercase_enforced, email):
        return True, ""
    
    parts = email.split('@')
    if "@" not in email: return False, "Email must contain an '@' symbol."
    if len(parts) > 2: return False, "Email must contain only one '@' symbol."
    local_part, domain_part = parts
    if not local_part: return False, "Email local part (before @) cannot be empty."
    if not domain_part: return False, "Email domain part (after @) cannot be empty."
    if "." not in domain_part: return False, "Email domain must contain a '.' (e.g., example.com)."
    domain_parts = domain_part.split('.')
    if len(domain_parts) < 2 or not domain_parts[-1]: return False, "Email domain must have a valid top-level domain (e.g., .com, .org)."
    if re.search(r"[A-Z]", email.split('@')[0]) or (len(email.split('@')) > 1 and re.search(r"[A-Z]", email.split('@')[1].split('.')[0])):
         return False, "Email must use only lowercase letters in the address (before the last dot)."
    return False, "Invalid email format. Please check the overall structure (e.g., user@domain.com)."

# --- Password Strength Validation ---
def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Checks if the password meets strength requirements.
    """
    min_length = 8
    has_uppercase, has_lowercase, has_digit, has_special = False, False, False, False
    error_messages = []

    if len(password) < min_length: 
        error_messages.append(f"Password must be at least {min_length} characters long.")

    for char in password:
        if 'A' <= char <= 'Z': has_uppercase = True
        elif 'a' <= char <= 'z': has_lowercase = True
        elif '0' <= char <= '9': has_digit = True
        elif char in "!@#$%^&*()_+-=[]{}|;':\",.<>/?`~": has_special = True

    if not has_uppercase: error_messages.append("Password must contain at least one uppercase letter.")
    if not has_lowercase: error_messages.append("Password must contain at least one lowercase letter.")
    if not has_digit: error_messages.append("Password must contain at least one number.")
    if not has_special: error_messages.append("Password must contain at least one special character (!@#$%^&*...).")

    if error_messages:
        return False, "\n".join(error_messages)
    return True, ""

# --- AWS SES Email Verification ---
def verify_email_identity(ses_client, user_email: str) -> bool:
    """
    Triggers the Amazon SES email identity verification process for a given email.
    SES will send a verification email to the user.
    """
    if not ses_client:
        print("SES client not initialized. Skipping email verification.")
        return False

    try:
        response = ses_client.create_email_identity(
            EmailIdentity=user_email
        )
        print(f"Verification email initiated for {user_email}. SES Response: {response}")
        return True
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        error_message = e.response.get('Error', {}).get('Message')
        
        if error_code == 'AlreadyExistsException':
            print(f"SES verification for {user_email} already exists or is pending. Considering it initiated.")
            return True  # Consider it successful if it already exists/pending
        elif error_code == 'LimitExceededException':
            print(f"SES limit exceeded for creating identities. Error: {error_message}")
            return False
        else:
            print(f"Failed to initiate SES verification for {user_email}: {error_message} (Code: {error_code})")
            return False
    except Exception as e:
        print(f"An unexpected error occurred while calling SES for {user_email}: {e}")
        return False

def check_email_verification_status(ses_client, user_email: str) -> bool:
    """
    Checks the verification status of an email identity in Amazon SES.
    Returns True if verified for sending, False otherwise or on error.
    """
    if not ses_client:
        print("SES client not initialized. Cannot check email verification status.")
        return False

    try:
        # Use list_identities to check if the email is verified
        response = ses_client.list_identities(
            IdentityType='EmailAddress'
        )
        
        if user_email in response.get('Identities', []):
            # Email exists in SES, now check its verification status
            try:
                # Try to get the identity details
                identity_response = ses_client.get_identity_verification_attributes(
                    Identities=[user_email]
                )
                
                verification_attrs = identity_response.get('VerificationAttributes', {})
                user_verification = verification_attrs.get(user_email, {})
                
                # Check if verified for sending
                verification_status = user_verification.get('VerificationStatus', 'NotStarted')
                is_verified = verification_status == 'Success'
                
                print(f"Verification status for {user_email}: {verification_status} (verified: {is_verified})")
                return is_verified
                
            except ClientError as e:
                print(f"Error getting verification attributes for {user_email}: {e}")
                return False
        else:
            print(f"Email identity {user_email} not found in SES. Verification not initiated.")
            return False
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        error_message = e.response.get('Error', {}).get('Message')
        print(f"Error checking SES verification status for {user_email}: {error_message} (Code: {error_code})")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while checking SES status for {user_email}: {e}")
        return False
