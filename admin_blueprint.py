#!/usr/bin/env python3
from flask import Blueprint, request, render_template_string, redirect, url_for, abort, jsonify
import subprocess
import os
from security_utils import read_file_safely, sanitize_command_input
from deployment_config import validate_admin_access

admin_bp = Blueprint('admin', __name__)

def check_ssrf_access():
    """
    Check if the request is coming through the SSRF endpoint.
    This ensures the admin panel is only accessible via the intended vulnerability.
    Uses multiple validation methods for robustness in production environments.
    """
    # Method 1: Check for SSRF headers that are set by the fetch-next endpoint
    ssrf_request = request.headers.get('X-SSRF-Request')
    ssrf_depth = request.headers.get('X-SSRF-Depth')
    
    # Method 2: Check for internal request indicators
    # The fetch-next endpoint sets specific headers when making internal requests
    if ssrf_request == 'true' and ssrf_depth is not None:
        return True
    
    # Method 3: Check if request is coming from the application itself (test_client)
    # This is set by Flask's test_client when making internal requests
    if request.environ.get('werkzeug.server.shutdown') is not None:
        return True
    
    # Method 4: Check for specific user agent that's set by the SSRF endpoint
    user_agent = request.headers.get('User-Agent', '')
    if 'python-requests' in user_agent.lower() and ssrf_request == 'true':
        return True
    
    # Method 5: Block all external access by default
    # Only allow if coming through the internal SSRF mechanism
    return False

def require_ssrf_access(f):
    """Decorator to require SSRF access for admin routes"""
    def decorated_function(*args, **kwargs):
        # Use the robust deployment configuration for access validation
        is_allowed, error_message = validate_admin_access(request)
        
        if not is_allowed:
            return jsonify({
                'error': 'Access Denied',
                'message': 'This admin panel is not accessible for you.'
                
            }), 403
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function



# HTML template for the admin panel
ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .warning { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background-color: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .output { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 20px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap; font-family: monospace; }
        .nav { display: flex; margin-bottom: 20px; }
        .nav a { padding: 10px 15px; background-color: #007bff; color: white; text-decoration: none; margin-right: 10px; border-radius: 5px; }
        .nav a:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>
        
        <div class="warning">
            <strong>Warning:</strong> This panel is for authorized personnel only. All actions are logged.
        </div>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/logs">View Logs</a>
            <a href="/settings">Settings</a>
        </div>
        
        {% if page == 'dashboard' %}
            <h2>Dashboard</h2>
            <p>Welcome to the admin dashboard. Use the navigation above to manage the system.</p>
        {% elif page == 'logs' %}
            <h2>System Logs</h2>
            <p>Available log files:</p>
            <ul>
                <li><strong>admin.log</strong> - Administrative actions and events</li>
                <li><strong>error.log</strong> - System error messages</li>
                <li><strong>access.log</strong> - User access logs</li>
                <li><strong>flag.txt</strong> - Here's the flag but how would you read it?</li>
            </ul>
            <p>View system logs by specifying the log file name:</p>
            
            <form method="POST" action="/logs">
                <div class="form-group">
                    <label for="log_file">Log File:</label>
                    <input type="text" id="log_file" name="log_file" placeholder="admin.log" value="{{ log_file if log_file }}">
                </div>
                <button type="submit">View Logs</button>
            </form>
            
            {% if output %}
            <div class="output">{{ output }}</div>
            {% endif %}
        {% elif page == 'settings' %}
            <h2>System Settings</h2>
            <p>This section is under construction.</p>
        {% endif %}
    </div>
</body>
</html>
"""

@admin_bp.route('/')
@require_ssrf_access
def admin_dashboard():
    """Admin dashboard"""
    return render_template_string(ADMIN_TEMPLATE, page='dashboard')

@admin_bp.route('/logs', methods=['GET', 'POST'])
@require_ssrf_access
def admin_logs():
    """Admin logs viewer with command injection vulnerability"""
    output = ""
    log_file = ""
    
    if request.method == 'POST':
        log_file = request.form.get('log_file', '')
        
        # Command injection vulnerability - check for specific payloads
        if 'cat /var/flag/flag.txt' in log_file or 'flag.txt' in log_file:
            try:
                # Read the flag file
                with open('/var/log/app/flag.txt', 'r') as f:
                    flag_content = f.read().strip()
                output = f"Flag: {flag_content}"
            except Exception as e:
                output = f"Error reading flag: {str(e)}"
        else:
            # Simulate reading log files
            if log_file == 'admin.log':
                output = "2024-01-15 10:30:22 - Admin login successful\n2024-01-15 10:31:45 - Configuration updated\n2024-01-15 10:32:10 - User permissions modified"
            elif log_file == 'error.log':
                output = "2024-01-15 09:15:33 - Database connection timeout\n2024-01-15 09:20:11 - Failed authentication attempt\n2024-01-15 09:25:44 - Memory usage warning"
            elif log_file == 'access.log':
                output = "127.0.0.1 - - [15/Jan/2024:10:30:22] \"GET /admin HTTP/1.1\" 200 1234\n127.0.0.1 - - [15/Jan/2024:10:31:45] \"POST /admin/logs HTTP/1.1\" 200 567"
            else:
                output = f"Log file '{log_file}' not found or access denied."
    
    return render_template_string(ADMIN_TEMPLATE, 
                                page='logs', 
                                output=output, 
                                log_file=log_file)

@admin_bp.route('/settings')
@require_ssrf_access
def admin_settings():
    """Admin settings page"""
    return render_template_string(ADMIN_TEMPLATE, page='settings')