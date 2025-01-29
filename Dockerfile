# Use a lightweight Python base image
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl jq \
    && rm -rf /var/lib/apt/lists/*

# Install the VirusTotal Python API client
RUN pip install vt-py

# Set up working directory
WORKDIR /app

# Copy script into the container
COPY scan.py /scan.py
RUN chmod +x /scan.py

# Create directories for file storage
RUN mkdir -p /app/files /app/quarantine

# Set default command to run the scanner
CMD ["python", "/scan.py"]
