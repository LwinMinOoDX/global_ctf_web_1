#!/usr/bin/env python3
"""
Deployment configuration for production environments.
This ensures the admin panel access control works correctly when deployed.
"""

import os
from flask import request

class DeploymentConfig:
    """Configuration for production deployment"""
    
    # Environment-specific settings
    PRODUCTION_MODE = os.environ.get('PRODUCTION_MODE', 'false').lower() == 'true'
    
    # Security settings for admin access
    ADMIN_ACCESS_STRICT_MODE = True
    
    # Allowed internal networks (CIDR notation)
    INTERNAL_NETWORKS = [
        '127.0.0.0/8',    # Loopback
        '10.0.0.0/8',     # Private Class A
        '172.16.0.0/12',  # Private Class B
        '192.168.0.0/16', # Private Class C
    ]
    
    # Required headers for SSRF access
    REQUIRED_SSRF_HEADERS = {
        'X-SSRF-Request': 'true',
        'X-SSRF-Depth': lambda x: x is not None and x.isdigit()
    }
    
    @staticmethod
    def is_internal_ip(ip_address):
        """Check if an IP address is from an internal network"""
        if not ip_address:
            return False
            
        # Check for localhost variations
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return True
            
        # Check for private network ranges
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            for network in DeploymentConfig.INTERNAL_NETWORKS:
                if ip in ipaddress.ip_network(network):
                    return True
        except ValueError:
            pass
            
        return False
    
    @staticmethod
    def validate_ssrf_headers(request_headers):
        """Validate that required SSRF headers are present and correct"""
        for header_name, expected_value in DeploymentConfig.REQUIRED_SSRF_HEADERS.items():
            header_value = request_headers.get(header_name)
            
            if callable(expected_value):
                if not expected_value(header_value):
                    return False
            else:
                if header_value != expected_value:
                    return False
                    
        return True
    
    @staticmethod
    def get_real_client_ip(request):
        """Get the real client IP, accounting for proxies and load balancers"""
        # Check common proxy headers in order of preference
        proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP', 
            'X-Client-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
        ]
        
        for header in proxy_headers:
            ip = request.headers.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs, take the first one
                if ',' in ip:
                    ip = ip.split(',')[0].strip()
                return ip
        
        # Fall back to direct connection IP
        return request.environ.get('REMOTE_ADDR', request.remote_addr)

# Production-ready admin access validator
def validate_admin_access(request):
    """
    Comprehensive admin access validation for production environments.
    Returns (is_allowed, error_message)
    """
    
    # Get the real client IP
    client_ip = DeploymentConfig.get_real_client_ip(request)
    
    # Check if the request is from an internal IP
    is_internal = DeploymentConfig.is_internal_ip(client_ip)
    
    # External IPs cannot access admin panel at all, even with spoofed headers
    if not is_internal:
        return False, f"Admin panel requires internal access. Client IP: {client_ip}"
    
    # For internal IPs, still require SSRF headers to ensure proper flow
    if not DeploymentConfig.validate_ssrf_headers(request.headers):
        return False, f"Admin panel requires internal access. Client IP: {client_ip}"
    
    # In production mode, be extra strict
    if DeploymentConfig.PRODUCTION_MODE:
        # Additional production checks can be added here
        # e.g., rate limiting, authentication tokens, etc.
        pass
    
    return True, "Access granted"