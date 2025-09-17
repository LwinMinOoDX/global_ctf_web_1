# Global CTF Web Challenge 1

A Flask-based web application designed for Capture The Flag (CTF) competitions. This challenge focuses on web security vulnerabilities including SSRF (Server-Side Request Forgery) and privilege escalation.

## 🎯 Challenge Overview

This CTF challenge presents a multi-layered web application with the following components:
- **Blog System**: Public-facing blog with posts and content
- **Admin Panel**: Restricted administrative interface
- **Log Viewer**: System log access functionality
- **SSRF Vulnerability**: Intentional security flaw for exploitation

## 🏗️ Architecture

The application consists of several Flask blueprints:
- `blog_blueprint.py` - Main blog functionality
- `admin_blueprint.py` - Administrative interface
- `logs_blueprint.py` - Log viewing system
- `security_utils.py` - Security utilities and helpers

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Pull from DockerHub:**
   ```bash
   docker pull <your-dockerhub-username>/global_ctf_web1:latest
   ```

2. **Run the container:**
   ```bash
   docker run -p 8080:80 <your-dockerhub-username>/global_ctf_web1:latest
   ```

3. **Access the application:**
   - Open your browser to `http://localhost:8080`

### Building from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/global_ctf_web1.git
   cd global_ctf_web1
   ```

2. **Build Docker image:**
   ```bash
   docker build -t global_ctf_web1 .
   ```

3. **Run the container:**
   ```bash
   docker run -p 8080:80 global_ctf_web1
   ```

### Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Access at:** `http://localhost:80`

## 🔍 Challenge Hints

- Explore the `/fetch-next` endpoint
- Look for ways to access internal services
- Check for administrative interfaces
- Examine log files for sensitive information
- The flag format is: `BCTF{...}`

## 🛡️ Security Features

This challenge implements several security measures to create a realistic CTF environment:
- Non-root user execution
- Restricted file permissions
- Removal of dangerous system binaries
- Limited network access
- Secure environment variables

## 📁 Project Structure

```
.
├── Dockerfile              # Container configuration
├── app.py                 # Main Flask application
├── blog_blueprint.py      # Blog functionality
├── admin_blueprint.py     # Admin interface
├── logs_blueprint.py      # Log viewer
├── security_utils.py      # Security utilities
├── requirements.txt       # Python dependencies
├── static/               # Static assets
└── templates/            # HTML templates
    ├── base.html
    ├── index.html
    ├── post.html
    ├── about.html
    ├── contact.html
    └── error.html
```

## 🐳 Docker Configuration

The Docker container is configured with:
- Python 3.9 slim base image
- Non-root user execution
- Restricted file permissions
- Minimal attack surface
- Port 80 exposure

## 🔧 Technical Details

- **Framework**: Flask 2.3.3
- **Python Version**: 3.9
- **Port**: 80 (mapped to host port 8080)
- **User**: Non-root (appuser)
- **Base Image**: python:3.9-slim

## 🏆 CTF Information

- **Difficulty**: Beginner to Intermediate
- **Categories**: Web Security, SSRF, Privilege Escalation
- **Flag Location**: Hidden in system logs
- **Estimated Time**: 30-60 minutes

## 📝 License

This project is created for educational purposes in CTF competitions.

## 🤝 Contributing

This is a CTF challenge repository. Please do not submit solutions or spoilers in issues or pull requests.

## ⚠️ Disclaimer

This application contains intentional security vulnerabilities for educational purposes. Do not deploy in production environments.