# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for some packages
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip setuptools wheel

# Copy requirements
COPY requirements.txt .

# Install Python packages
# Note: tensorflow takes time to install, be patient!
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Expose port for API
EXPOSE 8000

# Run the FastAPI application
CMD ["python", "api/main.py"]