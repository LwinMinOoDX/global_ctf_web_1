FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user with minimal privileges
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/false appuser

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies as root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create log directories and files (for CTF challenges) with restricted permissions
RUN mkdir -p /var/log/app && \
    echo "Admin access logged at $(date)" > /var/log/app/admin.log && \
    echo "System error: Connection timeout" > /var/log/app/error.log && \
    echo "User login: admin@example.com" > /var/log/app/access.log && \
    echo "System log entry" > /var/log/app/system.log

# Create flag directory and generate dynamic flag for CTF
RUN echo "BCTF{B1ND3Rl@bs_W3B_Ch411eN9E_n0-1}" > /var/log/app/flag.txt
# Copy application files
COPY . .

# Set strict permissions on log directory and app files
# Only the appuser can read files in /var/log/app, no write or execute permissions
RUN chown -R appuser:appuser /var/log/app /app && \
    chmod -R 400 /var/log/app/* && \
    chmod 500 /var/log/app && \
    chmod -R 500 /app && \
    chmod 400 /app/*.py

# Remove dangerous binaries and tools to prevent reverse shells and privilege escalation
# Do this as the last RUN command since we need /bin/sh for Docker RUN commands
RUN rm -f /bin/sh /bin/bash /bin/dash /bin/zsh /usr/bin/wget \
    /usr/bin/nc /usr/bin/netcat /usr/bin/telnet /usr/bin/ssh /usr/bin/scp \
    /usr/bin/rsync /usr/bin/ftp /usr/bin/sftp \
    /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg /usr/bin/pip /usr/bin/pip3 \
    /usr/bin/gcc /usr/bin/g++ /usr/bin/make /usr/bin/cmake \
    /usr/bin/vi /usr/bin/vim /usr/bin/nano /usr/bin/emacs \
    /bin/cat /usr/bin/less /usr/bin/more /usr/bin/head /usr/bin/tail \
    /usr/bin/grep /usr/bin/find /usr/bin/locate /usr/bin/which \
    /usr/bin/whoami /usr/bin/id /usr/bin/ps /usr/bin/top \
    /usr/bin/kill /usr/bin/killall /bin/mount /bin/umount \
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd || true

# Switch to non-root user
USER appuser

# Expose port 80
EXPOSE 80

# Set security-focused environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/app

# Run the combined Flask application with restricted capabilities
CMD ["python3.9", "app.py"]