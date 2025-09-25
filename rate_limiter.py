import time
from collections import defaultdict, deque
from flask import request, jsonify, Response
from functools import wraps
import threading

def rate_limit_banner():
    """Generate HTML banner for rate limiting"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rate Limit Exceeded</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .banner {
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                text-align: center;
                max-width: 500px;
                margin: 20px;
                animation: slideIn 0.5s ease-out;
            }
            @keyframes slideIn {
                from { transform: translateY(-50px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
            .warning-icon {
                font-size: 4rem;
                color: #ff6b6b;
                margin-bottom: 20px;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 20px;
                font-size: 2rem;
                font-weight: 600;
            }
            .message {
                color: #555;
                font-size: 1.1rem;
                line-height: 1.6;
                margin-bottom: 30px;
            }
            .countdown {
                background: #ff6b6b;
                color: white;
                padding: 15px 30px;
                border-radius: 25px;
                font-size: 1.2rem;
                font-weight: bold;
                display: inline-block;
                margin-bottom: 20px;
            }
            .info {
                background: #f8f9fa;
                border-left: 4px solid #007bff;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
                text-align: left;
            }
            .retry-btn {
                background: #007bff;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 25px;
                font-size: 1rem;
                cursor: pointer;
                transition: background 0.3s;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
            .retry-btn:hover {
                background: #0056b3;
            }
        </style>
    </head>
    <body>
        <div class="banner">
            <div class="warning-icon">Warning</div>
            <h1>You're Banned for 1 Minute!</h1>
            <div class="message">
                You have exceeded the rate limit of <strong>5 requests per second</strong>.
                <br>Your IP address has been temporarily blocked.
            </div>
            <div class="countdown">Please wait 60 seconds to continue your activity</div>
            <div class="info">
                <strong>Rate Limit Policy:</strong><br>
                • Maximum 5 requests per second per IP<br>
                • Block duration: 1 minute<br>
                • This helps protect our servers from abuse
            </div>
            <a href="javascript:location.reload()" class="retry-btn">Retry</a>
        </div>
        <script>
            // Auto-refresh after 60 seconds
            setTimeout(function() {
                location.reload();
            }, 60000);
        </script>
    </body>
    </html>
    """

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
rate_limiter = RateLimiter(max_requests=5, time_window=1, block_duration=60)

def rate_limit(f):
    """Decorator to apply rate limiting to Flask routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = rate_limiter.get_client_ip()
        
        # Check if IP is currently blocked
        if rate_limiter.is_blocked(ip_address):
            return Response(rate_limit_banner(), status=429, mimetype='text/html')
        
        # Check if this request should trigger a block
        if rate_limiter.should_block(ip_address):
            return Response(rate_limit_banner(), status=429, mimetype='text/html')
        
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
            return Response(rate_limit_banner(), status=429, mimetype='text/html')
        
        # Check if this request should trigger a block
        if rate_limiter.should_block(ip_address):
            return Response(rate_limit_banner(), status=429, mimetype='text/html')