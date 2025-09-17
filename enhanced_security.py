#!/usr/bin/env python3
import re
import urllib.parse
import json

class SecurityFilter:
    """
    Enhanced security filter to prevent reverse shells and unauthorized services
    while maintaining the intended SSRF functionality for CTF challenges.
    """
    
    # Comprehensive list of reverse shell and malicious command patterns
    DANGEROUS_PATTERNS = [
        # Common reverse shell commands
        r'bash\s*-i',
        r'sh\s*-i',
        r'/bin/bash',
        r'/bin/sh',
        r'nc\s+.*\s+-e',
        r'netcat\s+.*\s+-e',
        r'ncat\s+.*\s+-e',
        r'socat\s+.*exec',
        r'python.*socket',
        r'perl.*socket',
        r'ruby.*socket',
        r'php.*socket',
        r'telnet\s+\d+',
        
        # Base64 encoded common reverse shells
        r'YmFzaCAtaQ==',  # bash -i
        r'L2Jpbi9iYXNo',   # /bin/bash
        r'L2Jpbi9zaA==',   # /bin/sh
        
        # Process execution
        r'exec\s*\(',
        r'system\s*\(',
        r'popen\s*\(',
        r'subprocess',
        r'os\.system',
        r'os\.popen',
        r'eval\s*\(',
        
        # Network services
        r'python.*-m\s+http\.server',
        r'python.*-m\s+SimpleHTTPServer',
        r'php\s+-S',
        r'ruby\s+-run',
        r'node.*http',
        
        # File operations that could be dangerous
        r'wget\s+.*\|\s*sh',
        r'curl\s+.*\|\s*sh',
        r'curl\s+.*\|\s*bash',
        r'wget\s+.*\|\s*bash',
        
        # Command chaining
        r'&&',
        r'\|\|',
        r';\s*\w+',
        r'\|\s*\w+',
        
        # Environment manipulation
        r'export\s+',
        r'unset\s+',
        r'alias\s+',
        
        # Process control
        r'kill\s+',
        r'killall\s+',
        r'pkill\s+',
        r'nohup\s+',
        r'screen\s+',
        r'tmux\s+',
        
        # File system manipulation
        r'chmod\s+\+x',
        r'chown\s+',
        r'mount\s+',
        r'umount\s+',
        
        # Encoding/decoding that could hide payloads
        r'base64\s+-d',
        r'xxd\s+-r',
        r'uudecode',
        
        # Scripting languages with potential for abuse
        r'awk\s+.*system',
        r'sed\s+.*e',
        r'find\s+.*-exec',
        r'xargs\s+.*sh',
    ]
    
    # Compile patterns for better performance
    COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in DANGEROUS_PATTERNS]
    
    # Allowed URL paths for the CTF challenge
    ALLOWED_PATHS = [
        '/admin',
        '/admin/',
        '/admin/logs',
        '/admin/settings',
        '/logs',
        '/',
        ''
    ]
    
    # Allowed query parameters
    ALLOWED_QUERY_PARAMS = ['log_file']
    
    @classmethod
    def validate_url(cls, url):
        """
        Validate URL to ensure it only contains safe paths and parameters.
        Returns (is_valid: bool, error_message: str)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check if path is allowed
            if parsed.path not in cls.ALLOWED_PATHS:
                return False, f"Path '{parsed.path}' is not allowed"
            
            # Parse and validate query parameters
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                for param_name, param_values in query_params.items():
                    if param_name not in cls.ALLOWED_QUERY_PARAMS:
                        return False, f"Query parameter '{param_name}' is not allowed"
                    
                    # Check each parameter value for dangerous patterns
                    for value in param_values:
                        if not cls.is_safe_content(value):
                            return False, f"Dangerous content detected in parameter '{param_name}'"
            
            return True, ""
            
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"
    
    @classmethod
    def validate_form_data(cls, form_data):
        """
        Validate form data to prevent malicious payloads.
        Returns (is_valid: bool, error_message: str)
        """
        if not form_data:
            return True, ""
        
        for key, value in form_data.items():
            # Check key names
            if not cls.is_safe_content(key):
                return False, f"Dangerous content detected in form key '{key}'"
            
            # Check values
            if isinstance(value, list):
                for v in value:
                    if not cls.is_safe_content(str(v)):
                        return False, f"Dangerous content detected in form value for '{key}'"
            else:
                if not cls.is_safe_content(str(value)):
                    return False, f"Dangerous content detected in form value for '{key}'"
        
        return True, ""
    
    @classmethod
    def is_safe_content(cls, content):
        """
        Check if content is safe (doesn't contain dangerous patterns).
        Returns True if safe, False if dangerous.
        """
        if not content:
            return True
        
        content_str = str(content)
        
        # Check against all dangerous patterns
        for pattern in cls.COMPILED_PATTERNS:
            if pattern.search(content_str):
                return False
        
        return True
    
    @classmethod
    def filter_response_content(cls, content, content_type='text/html'):
        """
        Filter response content to prevent leaking dangerous information.
        Returns filtered content.
        """
        if not content:
            return content
        
        # For HTML responses, we want to preserve the admin panel functionality
        # but remove any potential shell output or dangerous content
        if 'html' in content_type.lower():
            # Remove any potential shell command output patterns
            shell_output_patterns = [
                r'total\s+\d+',  # ls -l output
                r'drwx.*',       # directory listings
                r'-rw-.*',       # file listings
                r'root:.*',      # passwd file content
                r'bin:.*',       # passwd file content
                r'daemon:.*',    # passwd file content
                r'\$\s+\w+',     # shell prompts
                r'#\s+\w+',      # root shell prompts
            ]
            
            for pattern in shell_output_patterns:
                content = re.sub(pattern, '[FILTERED]', content, flags=re.IGNORECASE | re.MULTILINE)
        
        return content
    
    @classmethod
    def validate_request(cls, url, form_data=None):
        """
        Comprehensive request validation.
        Returns (is_valid: bool, error_message: str)
        """
        # Validate URL
        url_valid, url_error = cls.validate_url(url)
        if not url_valid:
            return False, f"URL validation failed: {url_error}"
        
        # Validate form data
        form_valid, form_error = cls.validate_form_data(form_data)
        if not form_valid:
            return False, f"Form data validation failed: {form_error}"
        
        return True, ""