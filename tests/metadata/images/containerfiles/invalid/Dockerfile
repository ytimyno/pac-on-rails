FROM ubuntu:20.04

LABEL com.domain.maintainer="John Doe" version='1.0="hello"' maintainer_specific="myemail.com"

# Install necessary packages
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY . /app

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8080

# Define entrypoint
ENTRYPOINT ["python3", "app.py"]