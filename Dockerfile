# Use official lightweight Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_DEBUG=False
ENV FLASK_HOST=0.0.0.0
ENV PORT=8080

# Set working directory
WORKDIR /app

# Install system dependencies if required (none needed for standard requirements)
# Copy requirements first for Docker caching efficiency
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# SECURITY HARDENING: Create a non-privileged user and group to run the app
# Running containers as root is a major security risk (privilege escalation)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser && \
    chown -R appuser:appgroup /app

# Switch context to the non-root user
USER appuser

# Expose port (Cloud Run overrides this via the $PORT env, but 8080 is standard default)
EXPOSE 8080

# Launch application
CMD ["python", "app.py"]
