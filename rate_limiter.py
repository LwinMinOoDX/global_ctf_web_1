import time
from collections import defaultdict, deque
from flask import request, jsonify
from functools import wraps
import threading

class RateLimiter:
    def __init__(self, max_requests=3, time_window=1, block_duration=60):
        """
        Rate limiter that blocks IPs for a specified duration
        
        Args:
            max_requests (int): Maximum requests allowed per time window
            time_window (int): Time window in seconds (default: 1 second)
            block_duration (int): How long to block IP in seconds (default: 60 seconds)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.block_duration = block_duration
        
        # Track request timestamps for each IP
        self.request_history = defaultdict(deque)
        
        # Track blocked IPs and their unblock time
        self.blocked_ips = {}
        
        # Thread lock for thread safety
        self.lock = threading.Lock()
    
    def is_blocked(self, ip_address):
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip_address in self.blocked_ips:
                unblock_time = self.blocked_ips[ip_address]
                if time.time() < unblock_time:
                    return True
                else:
                    # IP block has expired, remove it
                    del self.blocked_ips[ip_address]
                    return False
            return False
    
    def should_block(self, ip_address):
        """Check if an IP should be blocked based on request rate"""
        current_time = time.time()
        
        with self.lock:
            # Clean old requests outside the time window
            request_times = self.request_history[ip_address]
            while request_times and current_time - request_times[0] > self.time_window:
                request_times.popleft()
            
            # Add current request
            request_times.append(current_time)
            
            # Check if rate limit exceeded
            if len(request_times) > self.max_requests:
                # Block the IP
                self.blocked_ips[ip_address] = current_time + self.block_duration
                # Clear request history for blocked IP
                self.request_history[ip_address].clear()
                return True
            
            return False
    
    def get_client_ip(self):
        """Get the real client IP address"""
        # Check for forwarded headers first (in case of proxy/load balancer)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    def cleanup_expired_blocks(self):
        """Clean up expired blocked IPs (optional maintenance)"""
        current_time = time.time()
        with self.lock:
            expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() 
                          if current_time >= unblock_time]
            for ip in expired_ips:
                del self.blocked_ips[ip]
    
    def get_status(self):
        """Get current rate limiter status for debugging"""
        with self.lock:
            return {
                'blocked_ips': len(self.blocked_ips),
                'tracked_ips': len(self.request_history),
                'blocked_list': list(self.blocked_ips.keys())
            }

# Global rate limiter instance
rate_limiter = RateLimiter(max_requests=3, time_window=1, block_duration=60)

def rate_limit(f):
    """Decorator to apply rate limiting to Flask routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = rate_limiter.get_client_ip()
        
        # Check if IP is currently blocked
        if rate_limiter.is_blocked(ip_address):
            return jsonify({
                'error': 'Rate limit exceeded. IP blocked for 1 minute.',
                'ip': ip_address,
                'retry_after': 60
            }), 429
        
        # Check if this request should trigger a block
        if rate_limiter.should_block(ip_address):
            return jsonify({
                'error': 'Rate limit exceeded. IP blocked for 1 minute.',
                'ip': ip_address,
                'retry_after': 60
            }), 429
        
        # Request is allowed, proceed normally
        return f(*args, **kwargs)
    
    return decorated_function

def apply_rate_limiting_globally(app):
    """Apply rate limiting to all routes globally"""
    @app.before_request
    def check_rate_limit():
        # Skip rate limiting for static files
        if request.endpoint and request.endpoint.startswith('static'):
            return
        
        ip_address = rate_limiter.get_client_ip()
        
        # Check if IP is currently blocked
        if rate_limiter.is_blocked(ip_address):
            return jsonify({
                'error': 'Rate limit exceeded. IP blocked for 1 minute.',
                'ip': ip_address,
                'retry_after': 60
            }), 429
        
        # Check if this request should trigger a block
        if rate_limiter.should_block(ip_address):
            return jsonify({
                'error': 'Rate limit exceeded. IP blocked for 1 minute.',
                'ip': ip_address,
                'retry_after': 60
            }), 429