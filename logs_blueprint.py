#!/usr/bin/env python3
from flask import Blueprint, jsonify, request
import os
from security_utils import read_file_safely, sanitize_filename

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/')
def home():
    return jsonify({
        "service": "Logs Server",
        "status": "running",
        "endpoints": [
            "/logs/logs",
            "/logs/health"
        ]
    })

@logs_bp.route('/logs')
def logs():
    log_file = request.args.get('file', 'system.log')
    
    # Sanitize the filename to prevent path traversal
    safe_filename = sanitize_filename(log_file)
    if not safe_filename:
        return "Access denied: Invalid filename", 403, {'Content-Type': 'text/plain'}
    
    # Use secure file reading function
    success, content, error_msg = read_file_safely(safe_filename)
    if success:
        return content, 200, {'Content-Type': 'text/plain'}
    else:
        return error_msg, 403, {'Content-Type': 'text/plain'}

@logs_bp.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "message": "Logs service is running"
    })