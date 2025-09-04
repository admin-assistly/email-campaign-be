#!/usr/bin/env python3
"""
Email Cleaning Module for Email Campaign Backend
Cleans inbound emails to extract only the latest reply, removing quoted content and security banners.
Simplified version using only built-in Python libraries.
"""

import re
import html
from typing import Tuple, Optional


class EmailCleaner:
    """Enterprise-grade email cleaning utility for extracting reply-only content."""
    
    # Security banners to remove
    SECURITY_BANNERS = [
        r"CAUTION: This email originated from outside of Charter Global",
        r"This email originated from outside of Charter Global",
        r"CAUTION: This email originated from outside",
        r"Do not click links or open attachments unless you recognize the sender",
        r"This email is from an external sender",
        r"External email warning",
        # Gmail specific warnings
        r"You don't often get email from .+\. Learn why this is important",
        r"You don't often get email from .+\. Learn why this is important\.",
        r"You don't often get email from .+\. Learn why this is important Thank you for your email",
        r"Learn why this is important",
        # Generic Gmail warnings
        r"This message seems dangerous",
        r"Be careful with this message",
        r"Gmail blocked some images in this message",
        r"Images in this message are not displayed",
    ]
    
    # Quote markers to detect and truncate at
    QUOTE_MARKERS = [
        r"^On .+ wrote:$",
        r"^> On .+ wrote:$",
        r"^From: .+",
        r"^Sent: .+",
        r"^To: .+",
        r"^Subject: .+",
        r"^Date: .+",
        r"^Cc: .+",
        r"^Bcc: .+",
        r"^-----Original Message-----",
        r"^Original Message",
        r"^From: .+ Sent: .+ To: .+ Subject:",
    ]
    
    # HTML quote containers to remove (patterns)
    QUOTE_CONTAINERS = [
        r'<div[^>]*class="[^"]*gmail_quote[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*yahoo_quoted[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*outlook_quote[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*ms-outlook-quote[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*quote[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*quoted[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*reply[^"]*"[^>]*>.*?</div>',
        r'<div[^>]*class="[^"]*replied[^"]*"[^>]*>.*?</div>',
        r'<blockquote[^>]*type="cite"[^>]*>.*?</blockquote>',
        r'<blockquote[^>]*>.*?</blockquote>',  # Remove all blockquotes
    ]

    @classmethod
    def clean_email(cls, raw_html: Optional[str] = None, raw_text: Optional[str] = None) -> Tuple[str, bool]:
        """
        Clean email content to extract only the latest reply.
        
        Args:
            raw_html: Raw HTML content from email
            raw_text: Raw text content from email
            
        Returns:
            Tuple of (cleaned_html, quoted_content_removed)
        """
        if not raw_html and not raw_text:
            return "", False
            
        # Prefer HTML path if available
        if raw_html:
            try:
                return cls._clean_html(raw_html, raw_text)
            except Exception as e:
                print(f"[EMAIL_CLEANER] HTML cleaning failed: {e}, falling back to text")
                if raw_text:
                    return cls._clean_text(raw_text)
                else:
                    return "", False
        else:
            return cls._clean_text(raw_text)

    @classmethod
    def _clean_html(cls, html_content: str, raw_text: Optional[str] = None) -> Tuple[str, bool]:
        """Clean HTML content, removing quoted containers and security banners."""
        quoted_removed = False
        
        try:
            # Remove security banners
            html_content = cls._remove_html_security_banners(html_content)
            
            # Remove quote containers
            original_length = len(html_content)
            html_content = cls._remove_html_quote_containers(html_content)
            if len(html_content) < original_length:
                quoted_removed = True
            
            # Convert HTML to text for quote marker detection
            text_content = cls._html_to_text(html_content)
            
            # Truncate at quote markers
            if cls._truncate_at_quote_markers(text_content):
                quoted_removed = True
                # Find the truncation point and apply to HTML
                for marker_pattern in cls.QUOTE_MARKERS:
                    match = re.search(marker_pattern, text_content, re.IGNORECASE | re.MULTILINE)
                    if match:
                        # Convert back to HTML, but only the truncated part
                        truncated_text = text_content[:match.start()].strip()
                        html_content = cls._text_to_html(truncated_text)
                        break
            
            # If no truncation happened, try to extract just the first paragraph
            if not quoted_removed:
                # Look for the first meaningful content
                lines = text_content.split('\n')
                first_content = ""
                for line in lines:
                    stripped = line.strip()
                    if stripped and not any(re.search(marker, stripped, re.IGNORECASE) for marker in cls.QUOTE_MARKERS):
                        first_content = stripped
                        break
                
                if first_content:
                    html_content = cls._text_to_html(first_content)
                else:
                    # Fallback: convert the cleaned HTML to text and back to HTML
                    text_content = cls._html_to_text(html_content)
                    html_content = cls._text_to_html(text_content)
            
            # Sanitize the HTML
            html_content = cls._sanitize_html(html_content)
            
            return html_content, quoted_removed
            
        except Exception as e:
            print(f"[EMAIL_CLEANER] HTML cleaning error: {e}")
            # Fall back to text cleaning if text is provided
            if raw_text:
                return cls._clean_text(raw_text)
            else:
                # Try to extract text from the HTML
                text_content = cls._html_to_text(html_content)
                return cls._clean_text(text_content)

    @classmethod
    def _clean_text(cls, text_content: str) -> Tuple[str, bool]:
        """Clean text content using manual reply extraction."""
        if not text_content:
            return "", False
            
        # Remove security banners first
        cleaned_text = cls._remove_text_security_banners(text_content)
        
        # Extract latest reply manually
        latest_reply = cls._extract_latest_reply_manual(cleaned_text)
        
        # Convert to HTML
        cleaned_html = cls._text_to_html(latest_reply)
        
        # Determine if quoted content was removed
        quoted_removed = len(latest_reply.strip()) < len(cleaned_text.strip())
        
        return cleaned_html, quoted_removed

    @classmethod
    def _remove_html_security_banners(cls, html_content: str) -> str:
        """Remove security banner elements from HTML."""
        for banner_pattern in cls.SECURITY_BANNERS:
            # Remove divs containing banner text
            pattern = rf'<div[^>]*>.*?{re.escape(banner_pattern)}.*?</div>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
            
            # Remove paragraphs containing banner text
            pattern = rf'<p[^>]*>.*?{re.escape(banner_pattern)}.*?</p>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
        
        return html_content

    @classmethod
    def _remove_html_quote_containers(cls, html_content: str) -> str:
        """Remove quote container elements from HTML."""
        for container_pattern in cls.QUOTE_CONTAINERS:
            html_content = re.sub(container_pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
        
        return html_content

    @classmethod
    def _truncate_at_quote_markers(cls, text_content: str) -> bool:
        """Check if content should be truncated at quote markers."""
        for marker_pattern in cls.QUOTE_MARKERS:
            if re.search(marker_pattern, text_content, re.IGNORECASE | re.MULTILINE):
                return True
        return False

    @classmethod
    def _remove_text_security_banners(cls, text: str) -> str:
        """Remove security banners from text content."""
        lines = text.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Check if line contains any security banner
            if not any(re.search(banner, line, re.IGNORECASE) for banner in cls.SECURITY_BANNERS):
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    @classmethod
    def _extract_latest_reply_manual(cls, text: str) -> str:
        """Manual extraction of latest reply."""
        lines = text.split('\n')
        reply_lines = []
        
        for line in lines:
            stripped_line = line.strip()
            
            # Detect quote markers
            if any(re.search(marker, line, re.IGNORECASE) for marker in cls.QUOTE_MARKERS):
                break
            
            # Detect quote prefixes
            if line.lstrip().startswith('>'):
                break
            
            # Skip empty lines at the beginning
            if not reply_lines and not stripped_line:
                continue
            
            reply_lines.append(line)
        
        return '\n'.join(reply_lines).strip()

    @classmethod
    def _html_to_text(cls, html_content: str) -> str:
        """Convert HTML to text by removing tags."""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', html_content)
        # Decode HTML entities
        text = html.unescape(text)
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    @classmethod
    def _text_to_html(cls, text: str) -> str:
        """Convert text to simple HTML paragraphs."""
        if not text:
            return ""
        
        lines = text.split('\n')
        html_lines = []
        
        for line in lines:
            stripped_line = line.strip()
            if stripped_line:
                # Escape HTML entities
                escaped_line = html.escape(stripped_line)
                html_lines.append(f"<p>{escaped_line}</p>")
            else:
                # Empty line becomes a break
                html_lines.append("<br>")
        
        return '\n'.join(html_lines)

    @classmethod
    def _sanitize_html(cls, html_content: str) -> str:
        """Sanitize HTML to safe subset."""
        # Remove dangerous tags
        dangerous_tags = ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'button']
        for tag in dangerous_tags:
            pattern = rf'<{tag}[^>]*>.*?</{tag}>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
            pattern = rf'<{tag}[^>]*/?>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
        
        # Remove dangerous attributes
        dangerous_attrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'javascript:']
        for attr in dangerous_attrs:
            pattern = rf'{attr}="[^"]*"'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
            pattern = rf'{attr}=\'[^\']*\''
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
        
        # Remove javascript: URLs
        html_content = re.sub(r'href="javascript:[^"]*"', 'href="#"', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r"href='javascript:[^']*'", "href='#'", html_content, flags=re.IGNORECASE)
        
        return html_content


def clean_email_content(raw_html: Optional[str] = None, raw_text: Optional[str] = None) -> Tuple[str, bool]:
    """
    Main function to clean email content - SIMPLIFIED VERSION
    Extract only clean, readable text from emails.
    
    Args:
        raw_html: Raw HTML content from email
        raw_text: Raw text content from email
        
    Returns:
        Tuple of (clean_text_only, quoted_content_removed)
    """
    
    # Step 1: Get the best source text
    source_text = ""
    if raw_text:
        source_text = raw_text
    elif raw_html:
        # Extract text from HTML
        source_text = _extract_text_from_html(raw_html)
    else:
        return "", False
    
    # Step 2: Extract only the latest reply
    clean_reply, quoted_removed = _extract_latest_reply_simple(source_text)
    
    # Step 3: Return clean text only (no HTML conversion)
    return clean_reply.strip(), quoted_removed


def _extract_text_from_html(html_content: str) -> str:
    """Extract clean text from HTML content."""
    if not html_content:
        return ""
    
    # Remove script and style elements completely
    html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    # Replace paragraph tags with newlines to preserve structure
    html_content = re.sub(r'</p>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'</div>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'<br[^>]*>', '\n', html_content, flags=re.IGNORECASE)
    
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', '', html_content)
    
    # Decode HTML entities
    text = html.unescape(text)
    
    # Clean up whitespace but preserve line breaks
    lines = text.split('\n')
    cleaned_lines = []
    for line in lines:
        cleaned_line = re.sub(r'\s+', ' ', line.strip())
        if cleaned_line:
            cleaned_lines.append(cleaned_line)
    
    return '\n'.join(cleaned_lines)


def _extract_latest_reply_simple(text_content: str) -> Tuple[str, bool]:
    """
    Simple extraction of the latest reply from email text.
    Removes quoted content and signatures.
    """
    if not text_content:
        return "", False
    
    lines = text_content.split('\n')
    reply_lines = []
    quoted_removed = False
    
    # Common quote indicators - more specific patterns
    quote_patterns = [
        r'^On .+at .+PM .+wrote:',  # Outlook style "On Mon, Aug 18, 2025 at 4:48 PM <email> wrote:"
        r'^On .+at .+AM .+wrote:',  # Outlook style AM version
        r'^On .+\d{4}.+wrote:',     # Date with year in quote
        r'^From:\s*.+@.+',          # Email headers
        r'^Sent:\s*.+',
        r'^To:\s*.+@.+',
        r'^Subject:\s*.+',
        r'^Date:\s*.+',
        r'^-----Original Message-----',
        r'^> ',                     # Standard quote prefix
        r'^>>',                     # Multiple quote levels
    ]
    
    # Security banner patterns
    security_patterns = [
        r'CAUTION.*originated.*outside',
        r'This email originated from outside',
        r'Do not click links.*unless you recognize',
        r'External email warning',
        # Gmail specific warnings
        r'You don\'t often get email from .+\. Learn why this is important',
        r'Learn why this is important',
        r'This message seems dangerous',
        r'Be careful with this message',
        r'Gmail blocked some images in this message',
        r'Images in this message are not displayed',
    ]
    
    for line in lines:
        stripped_line = line.strip()
        
        # Skip empty lines at the beginning
        if not reply_lines and not stripped_line:
            continue
        
        # Skip common HTML titles and metadata
        if stripped_line.lower() in ['text-size', 'title', 'meta', 'html', 'head', 'body']:
            continue
        
        # Check for security banners - skip these lines
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in security_patterns):
            quoted_removed = True
            continue
        
        # Check for quote indicators - stop processing here
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in quote_patterns):
            quoted_removed = True
            break
        
        # Check for Outlook quote markers
        if 'wrote:' in line.lower() and ('at' in line.lower() or 'on' in line.lower()):
            quoted_removed = True
            break
        
        # Check for forwarded message indicators
        if re.search(r'forwarded.*message', line, re.IGNORECASE):
            quoted_removed = True
            break
        
        # Add line to reply if it has meaningful content
        if stripped_line and len(stripped_line) > 2:  # Ignore very short lines
            reply_lines.append(line)
    
    # Join the reply lines
    reply_text = '\n'.join(reply_lines).strip()
    
    # Further clean up common signature patterns
    signature_patterns = [
        r'\n--\s*\n.*',  # Standard signature delimiter
        r'\nBest regards.*',
        r'\nThanks.*\n.*',  # Thanks + name
        r'\nSent from my.*',  # Mobile signatures
    ]
    
    for pattern in signature_patterns:
        match = re.search(pattern, reply_text, re.DOTALL | re.IGNORECASE)
        if match:
            reply_text = reply_text[:match.start()].strip()
            quoted_removed = True
            break
    
    # Final cleanup
    reply_text = re.sub(r'\n+', '\n', reply_text)  # Multiple newlines to single
    reply_text = reply_text.strip()
    
    return reply_text, quoted_removed
