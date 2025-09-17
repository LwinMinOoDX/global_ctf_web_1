#!/usr/bin/env python3
from flask import Blueprint, request, render_template_string, redirect, url_for, abort
import subprocess
import os
from security_utils import read_file_safely, sanitize_command_input

admin_bp = Blueprint('admin', __name__)

def check_internal_access():
    """Check if the request is coming from localhost/internal network"""
    # Get the real IP address, considering potential proxies
    remote_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    if remote_addr:
        # Take the first IP if there are multiple (in case of proxy chain)
        remote_addr = remote_addr.split(',')[0].strip()
    
    # Allow localhost and internal network access
    allowed_ips = ['127.0.0.1', '::1', 'localhost']
    
    # Check if request is from allowed IPs or internal Docker network
    if remote_addr not in allowed_ips and not remote_addr.startswith('172.'):
        abort(404)  # Return 404 instead of 403 to hide the existence of admin panel

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
            <a href="{{ url_for('admin.dashboard') }}">Dashboard</a>
            <a href="{{ url_for('admin.logs') }}">View Logs</a>
            <a href="{{ url_for('admin.settings') }}">Settings</a>
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
            
            <form method="POST" action="{{ url_for('admin.logs') }}">
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
def dashboard():
    check_internal_access()
    return render_template_string(ADMIN_TEMPLATE, page='dashboard')

@admin_bp.route('/logs', methods=['GET', 'POST'])
def logs():
    check_internal_access()
    output = None
    log_file = None
    
    if request.method == 'POST':
        log_file = request.form.get('log_file', '')
        if log_file:
            # Sanitize input to prevent command injection and path traversal
            safe_filename = sanitize_command_input(log_file)
            if safe_filename:
                # Use secure file reading function
                success, content, error_msg = read_file_safely(safe_filename)
                if success:
                    output = content
                else:
                    output = error_msg
            else:
                output = "Access denied: Invalid filename or dangerous characters detected"
    
    return render_template_string(ADMIN_TEMPLATE, page='logs', output=output, log_file=log_file)

@admin_bp.route('/settings')
def settings():
    check_internal_access()
    return render_template_string(ADMIN_TEMPLATE, page='settings')