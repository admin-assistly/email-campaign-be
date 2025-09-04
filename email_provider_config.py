#!/usr/bin/env python3
"""
Dynamic Email Provider Configuration
Supports any email domain with automatic provider detection and configuration
"""

import re
import dns.resolver
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class EmailProviderConfig:
    """Dynamic email provider configuration and detection"""
    
    # Known provider configurations
    PROVIDER_CONFIGS = {
        'gmail.com': {
            'name': 'Gmail',
            'imap_server': 'imap.gmail.com',
            'imap_port': 993,
            'imap_ssl': True,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_ssl': False,
            'smtp_starttls': True,
            'oauth_provider': 'google',
            'auth_methods': ['oauth2', 'app_password'],
            'oauth_scopes': ['https://mail.google.com/'],
            'oauth_client_id_env': 'GOOGLE_CLIENT_ID',
            'oauth_client_secret_env': 'GOOGLE_CLIENT_SECRET'
        },
        'outlook.com': {
            'name': 'Outlook',
            'imap_server': 'outlook.office365.com',
            'imap_port': 993,
            'imap_ssl': True,
            'smtp_server': 'smtp-mail.outlook.com',
            'smtp_port': 587,
            'smtp_ssl': False,
            'smtp_starttls': True,
            'oauth_provider': 'microsoft',
            'auth_methods': ['oauth2'],
            'oauth_scopes': ['https://outlook.office365.com/IMAP.AccessAsUser.All'],
            'oauth_client_id_env': 'MICROSOFT_CLIENT_ID',
            'oauth_client_secret_env': 'MICROSOFT_CLIENT_SECRET'
        },
        'yahoo.com': {
            'name': 'Yahoo',
            'imap_server': 'imap.mail.yahoo.com',
            'imap_port': 993,
            'imap_ssl': True,
            'smtp_server': 'smtp.mail.yahoo.com',
            'smtp_port': 587,
            'smtp_ssl': False,
            'smtp_starttls': True,
            'oauth_provider': 'yahoo',
            'auth_methods': ['oauth2', 'app_password'],
            'oauth_scopes': ['mail-r'],
            'oauth_client_id_env': 'YAHOO_CLIENT_ID',
            'oauth_client_secret_env': 'YAHOO_CLIENT_SECRET'
        },
        'icloud.com': {
            'name': 'iCloud',
            'imap_server': 'imap.mail.me.com',
            'imap_port': 993,
            'imap_ssl': True,
            'smtp_server': 'smtp.mail.me.com',
            'smtp_port': 587,
            'smtp_ssl': False,
            'smtp_starttls': True,
            'oauth_provider': 'apple',
            'auth_methods': ['app_password'],  # iCloud uses app-specific passwords
            'oauth_scopes': [],
            'oauth_client_id_env': None,
            'oauth_client_secret_env': None
        }
    }
    
    # Common business email providers
    BUSINESS_PROVIDERS = {
        'office365.com': 'outlook.com',
        'hotmail.com': 'outlook.com',
        'live.com': 'outlook.com',
        'msn.com': 'outlook.com',
        'googlemail.com': 'gmail.com',
        'me.com': 'icloud.com',
        'mac.com': 'icloud.com'
    }
    
    @classmethod
    def detect_provider(cls, email_address: str) -> Dict:
        """Detect email provider configuration based on email address"""
        domain = email_address.lower().split('@')[1]
        
        # Check if it's a known provider
        if domain in cls.PROVIDER_CONFIGS:
            return cls.PROVIDER_CONFIGS[domain].copy()
        
        # Check if it's a business provider alias
        if domain in cls.BUSINESS_PROVIDERS:
            base_provider = cls.BUSINESS_PROVIDERS[domain]
            return cls.PROVIDER_CONFIGS[base_provider].copy()
        
        # Try to detect custom domain
        return cls._detect_custom_domain(domain)
    
    @classmethod
    def _detect_custom_domain(cls, domain: str) -> Dict:
        """Detect configuration for custom domains"""
        try:
            # Try to get MX records to determine provider
            mx_records = dns.resolver.resolve(domain, 'MX')
            
            for mx in mx_records:
                mx_domain = str(mx.exchange).lower()
                
                # Check for Google Workspace
                if 'google' in mx_domain or 'gmail' in mx_domain:
                    config = cls.PROVIDER_CONFIGS['gmail.com'].copy()
                    config['name'] = f'Google Workspace ({domain})'
                    config['custom_domain'] = domain
                    return config
                
                # Check for Microsoft 365
                if 'outlook' in mx_domain or 'office365' in mx_domain or 'microsoft' in mx_domain:
                    config = cls.PROVIDER_CONFIGS['outlook.com'].copy()
                    config['name'] = f'Microsoft 365 ({domain})'
                    config['custom_domain'] = domain
                    return config
                
                # Check for Yahoo Business
                if 'yahoo' in mx_domain:
                    config = cls.PROVIDER_CONFIGS['yahoo.com'].copy()
                    config['name'] = f'Yahoo Business ({domain})'
                    config['custom_domain'] = domain
                    return config
            
            # Default to generic IMAP configuration
            return cls._get_generic_imap_config(domain)
            
        except Exception as e:
            logger.warning(f"Could not detect provider for {domain}: {e}")
            return cls._get_generic_imap_config(domain)
    
    @classmethod
    def _get_generic_imap_config(cls, domain: str) -> Dict:
        """Get generic IMAP configuration for unknown domains"""
        return {
            'name': f'Custom IMAP ({domain})',
            'imap_server': f'imap.{domain}',
            'imap_port': 993,
            'imap_ssl': True,
            'smtp_server': f'smtp.{domain}',
            'smtp_port': 587,
            'smtp_ssl': False,
            'smtp_starttls': True,
            'oauth_provider': 'generic',
            'auth_methods': ['basic_auth', 'oauth2'],
            'oauth_scopes': [],
            'oauth_client_id_env': None,
            'oauth_client_secret_env': None,
            'custom_domain': domain,
            'requires_manual_config': True
        }
    
    @classmethod
    def get_oauth_config(cls, provider_config: Dict) -> Dict:
        """Get OAuth configuration for a provider"""
        oauth_provider = provider_config.get('oauth_provider')
        
        oauth_configs = {
            'google': {
                'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
                'token_url': 'https://oauth2.googleapis.com/token',
                'scope_separator': ' ',
                'redirect_uri': 'http://localhost:5000/api/auth/google/callback'
            },
            'microsoft': {
                'auth_url': 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize',
                'token_url': 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
                'scope_separator': ' ',
                'redirect_uri': 'http://localhost:5000/api/auth/microsoft/callback'
            },
            'yahoo': {
                'auth_url': 'https://api.login.yahoo.com/oauth2/request_auth',
                'token_url': 'https://api.login.yahoo.com/oauth2/get_token',
                'scope_separator': ' ',
                'redirect_uri': 'http://localhost:5000/api/auth/yahoo/callback'
            },
            'generic': {
                'auth_url': None,
                'token_url': None,
                'scope_separator': ' ',
                'redirect_uri': None
            }
        }
        
        return oauth_configs.get(oauth_provider, oauth_configs['generic'])
    
    @classmethod
    def validate_config(cls, provider_config: Dict) -> Tuple[bool, str]:
        """Validate provider configuration"""
        required_fields = ['imap_server', 'imap_port', 'name']
        
        for field in required_fields:
            if field not in provider_config:
                return False, f"Missing required field: {field}"
        
        # Check if OAuth is required but not configured
        if 'oauth2' in provider_config.get('auth_methods', []):
            oauth_config = cls.get_oauth_config(provider_config)
            if not oauth_config.get('auth_url'):
                return False, f"OAuth2 not supported for provider: {provider_config['name']}"
        
        return True, "Configuration is valid"
