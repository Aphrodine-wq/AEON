FROM python:3.11-slim

LABEL maintainer="AEON Project <hello@aeon-lang.dev>"
LABEL description="AEON — AI-native formal verification for 8 programming languages"
LABEL version="0.3.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Expose API server port
EXPOSE 8000

# Default: run the API server
CMD ["python", "-m", "aeon.api_server", "--port", "8000", "--host", "0.0.0.0"]
