# Build stage
FROM python:3.13-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements-mcp.txt .
RUN pip install --no-cache-dir --user -r requirements-mcp.txt

# Copy the package
COPY isilon_mcp/ ./isilon_mcp/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Install the package
RUN pip install --no-cache-dir --user .

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Copy installed packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application files
COPY isilon_mcp/ ./isilon_mcp/
COPY openapi.json ./openapi.json

# Set environment variables
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOCAL_OPENAPI_SPEC_PATH=/app/openapi.json

# Allowed HTTP methods for MCP tools (comma-separated)
# Options: GET, POST, PUT, PATCH, DELETE
# Default: GET (read-only) - change to "GET,POST,PUT,DELETE,PATCH" for full access
ENV ALLOWED_HTTP_METHODS=GET

# Switch to non-root user
USER appuser

# Expose HTTP server port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Default command: run HTTP server
CMD ["python", "-m", "uvicorn", "isilon_mcp.http_server:app", "--host", "0.0.0.0", "--port", "8000"]
