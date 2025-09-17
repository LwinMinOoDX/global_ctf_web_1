#!/usr/bin/env python3
import os
import re
from pathlib import Path

# Allowed log directory - restrict to only this directory
ALLOWED_LOG_DIR = "/var/log/app"

# Whitelist of allowed log files (only these files can be accessed)
ALLOWED_LOG_FILES = {
    'admin.log',
    'error.log', 
    'access.log',
    'system.log',
    'flag.txt'
}

def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and other attacks.
    Only allows alphanumeric characters, dots, hyphens, and underscores.
    """
    if not filename:
        return None
    
    # Remove any path separators and null bytes
    filename = filename.replace('/', '').replace('\\', '').replace('\0', '')
    
    # Only allow safe characters: alphanumeric, dot, hyphen, underscore
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return None
    
    # Prevent hidden files and parent directory references
    if filename.startswith('.') or '..' in filename:
        return None
    
    # Check against whitelist
    if filename not in ALLOWED_LOG_FILES:
        return None
    
    return filename

def validate_file_path(filename):
    """
    Validate and construct safe file path.
    Returns None if the path is not safe or file doesn't exist.
    """
    # Sanitize the filename first
    safe_filename = sanitize_filename(filename)
    if not safe_filename:
        return None
    
    # Construct the full path
    file_path = os.path.join(ALLOWED_LOG_DIR, safe_filename)
    
    # Resolve any symbolic links and normalize the path
    try:
        resolved_path = os.path.realpath(file_path)
    except (OSError, ValueError):
        return None
    
    # Ensure the resolved path is still within the allowed directory
    allowed_dir_real = os.path.realpath(ALLOWED_LOG_DIR)
    if not resolved_path.startswith(allowed_dir_real + os.sep) and resolved_path != allowed_dir_real:
        return None
    
    # Check if file exists and is a regular file (not a directory or special file)
    if not os.path.exists(resolved_path) or not os.path.isfile(resolved_path):
        return None
    
    return resolved_path

def sanitize_command_input(user_input):
    """
    Sanitize command input to prevent command injection.
    For CTF purposes, we'll make this very restrictive.
    """
    if not user_input:
        return None
    
    # Remove dangerous characters that could be used for command injection
    dangerous_chars = ['&', '|', ';', '$', '`', '(', ')', '{', '}', '[', ']', 
                      '<', '>', '!', '?', '*', '~', '^', '\n', '\r', '\t']
    
    for char in dangerous_chars:
        if char in user_input:
            return None
    
    # Only allow the whitelisted filenames
    return sanitize_filename(user_input)

def read_file_safely(filename):
    """
    Safely read a file with all security checks.
    Returns tuple (success: bool, content: str, error_message: str)
    """
    try:
        # Validate the file path
        safe_path = validate_file_path(filename)
        if not safe_path:
            return False, "", "Access denied: Invalid file or path"
        
        # Read the file with size limit to prevent memory exhaustion
        MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
        
        with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Check file size before reading
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            f.seek(0)  # Seek back to beginning
            
            if file_size > MAX_FILE_SIZE:
                return False, "", "File too large to display"
            
            content = f.read()
            return True, content, ""
            
    except PermissionError:
        return False, "", "Permission denied"
    except UnicodeDecodeError:
        return False, "", "File contains invalid characters"
    except Exception as e:
        return False, "", f"Error reading file: Access denied"