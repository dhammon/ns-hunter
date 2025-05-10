# Base image with Python
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy Python files and config
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command (can be overridden)
ENTRYPOINT ["python", "/app/src/hunt.py"]