#!/usr/bin/env python3
from flask import Flask, request, jsonify
import requests
import urllib.parse
from blog_blueprint import blog_bp
from admin_blueprint import admin_bp
from logs_blueprint import logs_bp

app = Flask(__name__)

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
        
        # Parse the URL to validate it
        parsed_url = urllib.parse.urlparse(url)
        
        # Only allow http scheme and specific hosts
        if parsed_url.scheme not in ['http']:
            return jsonify({'error': 'Only HTTP URLs are allowed'}), 400
        
        # Allow localhost and admin host
        allowed_hosts = ['localhost', '127.0.0.1', 'admin']
        if parsed_url.hostname not in allowed_hosts:
            return jsonify({'error': 'Host not allowed'}), 400
        
        # Construct the internal URL
        if parsed_url.hostname == 'admin':
            # Map admin host to localhost admin endpoint
            internal_url = f"http://127.0.0.1:80/admin{parsed_url.path}"
        else:
            internal_url = f"http://127.0.0.1:80{parsed_url.path}"
        
        # Add query parameters if they exist
        if parsed_url.query:
            internal_url += f"?{parsed_url.query}"
        
        # Make the internal request with form data if provided
        # Since we're making requests from localhost (127.0.0.1), they will be allowed
        
        # Forward any form data from the original request
        form_data = dict(request.form)
        if 'url' in form_data:
            del form_data['url']  # Remove the url parameter
        
        if form_data:
            response = requests.post(internal_url, data=form_data, timeout=5)
        else:
            response = requests.get(internal_url, timeout=5)
        
        # Return the response
        return response.text, response.status_code, {'Content-Type': response.headers.get('Content-Type', 'text/html')}
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Request failed: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Internal error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)