#!/usr/bin/env python3
from flask import Blueprint, request, render_template, redirect, url_for, jsonify
import requests
import os

blog_bp = Blueprint('blog', __name__, template_folder='templates/blog', static_folder='static')

# Sample blog posts
posts = [
    {
        'id': 1,
        'title': 'Welcome to Our Blog',
        'content': 'This is our first blog post. We hope you enjoy reading our content!',
        'author': 'Admin'
    },
    {
        'id': 2,
        'title': 'Web Security Basics',
        'content': 'Today we\'ll discuss some web security basics.Maybe',
        'author': 'Security Expert'
    },
    {
        'id': 3,
        'title': 'Owls quiz',
        'content': 'Are owl\'s eyes orbs or tubes?',
        'author': 'Economos'
    },
    {
        'id': 4,
        'title': 'Stupid Question?',
        'content': 'Is your favorite color teal?',
        'author': 'Some vigilante'
    },
    {
        'id': 5,
        'title': 'Bird blindness',
        'content': 'Bird blindness is real. Some people cannot tell if it\'s a duck or an eagle.',
        'author': 'Someone suffering from bird blindness'
    }
]

@blog_bp.route('/')
def home():
    return render_template('index.html', posts=posts)

@blog_bp.route('/post/<int:post_id>')
def post(post_id):
    # Find the post with the given ID
    post = next((p for p in posts if p['id'] == post_id), None)
    if not post:
        return render_template('error.html', error="Post not found"), 404
    
    # Get the previous and next post IDs for pagination
    prev_id = post_id - 1 if post_id > 1 else None
    next_id = post_id + 1 if post_id < len(posts) else None
    
    return render_template('post.html', post=post, prev_id=prev_id, next_id=next_id)

@blog_bp.route('/about')
def about():
    return render_template('about.html')

@blog_bp.route('/contact')
def contact():
    return render_template('contact.html')

@blog_bp.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "blog"})

@blog_bp.route('/ssrf-test')
def ssrf_test():
    return render_template('ssrf_test.html')

@blog_bp.route('/post/<int:post_id>/fetch-next', methods=['GET', 'POST'])
def post_fetch_next(post_id):
    """
    SSRF endpoint accessible from post pages
    This provides the same functionality as the main /fetch-next endpoint
    """
    import urllib.parse
    from flask import jsonify
    
    # Handle GET requests for endpoint information
    if request.method == 'GET' and not request.args.get('url'):
        return jsonify({
            'endpoint': f'/post/{post_id}/fetch-next',
            'method': 'POST',
            'description': 'Fetch content from external URLs',
            'parameters': {
                'url': 'The URL to fetch content from (query parameter)'
            },
            'example': f'curl -X POST "http://localhost:8082/post/{post_id}/fetch-next?url=http://admin/logs"',
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
        
        # For admin panel requests, directly call the admin functions
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
                response = requests.post(internal_url, data=form_data, timeout=3, allow_redirects=False)
            else:
                response = requests.get(internal_url, timeout=3, allow_redirects=False)
            
            content = response.text
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', 'text/html')
        
        # Return the response (simplified - no security filtering for CTF)
        return content, status_code, {'Content-Type': content_type}
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Request failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Internal error: {str(e)}'}), 500