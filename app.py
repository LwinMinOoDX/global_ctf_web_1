#!/usr/bin/env python3
from flask import Flask, request, jsonify
import requests
import urllib.parse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from blog_blueprint import blog_bp
from admin_blueprint import admin_bp
from logs_blueprint import logs_bp
from enhanced_security import SecurityFilter

app = Flask(__name__)

# Initialize Flask-Limiter with 5 requests per second for all endpoints
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per second"],
    storage_uri="memory://"
)
limiter.init_app(app)

# Register blueprints with their respective URL prefixes
app.register_blueprint(blog_bp, url_prefix='/')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(logs_bp, url_prefix='/logs')

@app.route('/fetch-next', methods=['GET', 'POST'])
def fetch_next():
    """
    SSRF endpoint that allows fetching internal URLs
    This is the intended way to access the admin panel
    """
    # Handle GET requests for endpoint information
    if request.method == 'GET' and not request.args.get('url'):
        return jsonify({
            'endpoint': '/fetch-next',
            'method': 'POST',
            'description': 'Fetch content from external URLs',
            'parameters': {
                'url': 'The URL to fetch content from (query parameter)'
            },
            'example': 'curl -X POST "http://localhost:8082/fetch-next?url=https://example.com"',
            'note': 'Supports internal URLs like admin, localhost'
        })
    
    try:
        # Get the URL parameter from query string
        url = request.args.get('url', '')
        if not url:
            return jsonify({'error': 'URL parameter is required'}), 400
        
        # Check request depth to prevent deep nested SSRF calls
        ssrf_depth = int(request.headers.get('X-SSRF-Depth', '0'))
        if ssrf_depth >= 2:
            return jsonify({'error': 'Maximum SSRF request depth exceeded for security reasons'}), 403
        
        # Enhanced security validation
        form_data = dict(request.form)
        if 'url' in form_data:
            del form_data['url']  # Remove the url parameter from form data
        
        # Security validation disabled for CTF - this creates the vulnerability
        # is_valid, error_message = SecurityFilter.validate_request(url, form_data)
        # if not is_valid:
        #     return jsonify({'error': f'Security validation failed: {error_message}'}), 400
        
        # Parse the URL to validate it
        parsed_url = urllib.parse.urlparse(url)
        
        # Only allow http scheme and specific hosts
        if parsed_url.scheme not in ['http']:
            return jsonify({'error': 'Only HTTP URLs are allowed'}), 400
        
        # Allow localhost and admin host for SSRF vulnerability
        allowed_hosts = ['localhost', '127.0.0.1', 'admin']
        if parsed_url.hostname not in allowed_hosts:
            return jsonify({'error': 'Host not allowed'}), 400
        
        # Construct the internal URL - map 'admin' hostname to localhost
        if parsed_url.hostname == 'admin':
            # Map admin hostname to localhost admin panel
            internal_url = f"http://127.0.0.1:80/admin{parsed_url.path}"
        else:
            internal_url = f"http://127.0.0.1:80{parsed_url.path}"
        
        # Add query parameters if they exist
        if parsed_url.query:
            internal_url += f"?{parsed_url.query}"
        
        # Make the internal request with form data if provided
        # Since we're making requests from localhost (127.0.0.1), they will be allowed
        
        # Forward any form data from the original request (already validated above)
        # Use strict timeout and connection limits to prevent abuse
        request_timeout = 3  # Short timeout to prevent hanging connections
        
        # For admin panel requests, directly call the admin functions to avoid redirects
        # Handle both http://admin and http://admin/ patterns, with or without port
        if (internal_url.startswith('http://admin/') or internal_url.startswith('http://127.0.0.1/admin/') or 
            internal_url.startswith('http://127.0.0.1:80/admin/') or internal_url.startswith('http://127.0.0.1:80/admin') or
            internal_url == 'http://admin' or internal_url == 'http://127.0.0.1/admin' or internal_url == 'http://127.0.0.1:80/admin' or
            internal_url.startswith('http://admin?') or internal_url.startswith('http://127.0.0.1/admin?') or
            internal_url.startswith('http://127.0.0.1:80/admin?')):
            from admin_blueprint import admin_bp
            from flask import Flask
            
            # Create a test client to directly call admin routes
            test_app = Flask(__name__)
            test_app.register_blueprint(admin_bp, url_prefix='/admin')
            
            with test_app.test_client() as client:
                # Extract the admin path and ensure it has proper format
                admin_path = internal_url.replace('http://admin', '/admin').replace('http://127.0.0.1/admin', '/admin').replace('http://127.0.0.1:80/admin', '/admin')
                
                # If the path is just /admin (without trailing slash), add it to match Flask routes
                if admin_path == '/admin':
                    admin_path = '/admin/'
                
                # Make the request directly to avoid any redirect issues
                # Set proper environment to simulate internal access
                # Add headers to track SSRF depth and indicate this is an SSRF request
                current_depth = int(request.headers.get('X-SSRF-Depth', '0'))
                environ_overrides = {
                    'REMOTE_ADDR': '127.0.0.1',
                    'HTTP_HOST': '127.0.0.1',
                    'SERVER_NAME': '127.0.0.1',
                    'HTTP_X_SSRF_REQUEST': 'true',
                    'HTTP_X_SSRF_DEPTH': str(current_depth + 1)
                }
                
                if form_data:
                    response = client.post(admin_path, data=form_data, environ_overrides=environ_overrides)
                else:
                    response = client.get(admin_path, environ_overrides=environ_overrides)
                
                # Get the response content
                content = response.get_data(as_text=True)
                status_code = response.status_code
                content_type = response.headers.get('Content-Type', 'text/html')
        else:
            # For non-admin requests, use regular HTTP requests
            if form_data:
                response = requests.post(internal_url, data=form_data, timeout=request_timeout, 
                                       allow_redirects=False)
            else:
                response = requests.get(internal_url, timeout=request_timeout, 
                                      allow_redirects=False)
            
            content = response.text
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', 'text/html')
        
        # Filter response content to prevent dangerous information leakage
        filtered_content = SecurityFilter.filter_response_content(content, content_type)
        
        # Return the filtered response
        return filtered_content, status_code, {'Content-Type': content_type}
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Request failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)