"""Configuration loader for Isilon MCP Server.

This module provides configuration management using Pydantic models
for validation and environment variable loading.

Example:
    >>> from isilon_mcp.config import load_config
    >>> config = load_config()
    >>> print(config.server.port)
    3000

Environment Variables:
    ISILON_HOST: Default PowerScale host (optional).
    ISILON_USERNAME: Default username (optional).
    ISILON_PASSWORD: Default password (optional).
    LOCAL_OPENAPI_SPEC_PATH: Path to OpenAPI spec file (required).
    HTTP_SERVER_PORT: HTTP server port (default: 3000).
    LOG_LEVEL: Logging level (default: INFO).
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

from .exceptions import ConfigurationError, EnvironmentVariableError
from .logging_config import get_logger

logger = get_logger(__name__)


class IsilonConfig(BaseModel):
    """Isilon/PowerScale connection configuration.

    Attributes:
        host: PowerScale host (optional, can be provided per-request).
        username: PowerScale username (optional).
        password: PowerScale password (optional).
        local_spec_path: Path to local OpenAPI spec file.
        tls_verify: Whether to verify TLS certificates.
        port: PowerScale API port (default: 8080).
    """

    host: str | None = Field(
        default="localhost",
        description="PowerScale host (optional, provided per-request)",
    )
    username: str | None = Field(
        default=None,
        description="PowerScale username (optional)",
    )
    password: str | None = Field(
        default=None,
        description="PowerScale password (optional)",
    )
    local_spec_path: str | None = Field(
        default=None,
        description="Local OpenAPI spec file path",
    )
    tls_verify: bool = Field(
        default=False,
        description="Verify TLS certificates",
    )
    port: int = Field(
        default=8080,
        description="PowerScale API port",
    )
    use_https: bool = Field(
        default=True,
        description="Use HTTPS instead of HTTP (default: True for PowerScale)",
    )

    @field_validator("local_spec_path")
    @classmethod
    def validate_spec_path(cls, v: str | None) -> str | None:
        """Validate that the OpenAPI spec path exists if provided.

        Args:
            v: The path value to validate.

        Returns:
            The validated path.

        Raises:
            ValueError: If the path doesn't exist.
        """
        if v is not None and not Path(v).exists():
            raise ValueError(f"OpenAPI spec file not found: {v}")
        return v

    model_config = {"extra": "ignore"}


class ServerConfig(BaseModel):
    """Server configuration.

    Attributes:
        port: HTTP server port.
        log_level: Logging level.
        log_json: Use JSON format for logs.
        log_file: Optional log file path.
        allowed_http_methods: List of allowed HTTP methods for tool generation.
        max_retries: Max API retry attempts.
        retry_delay: Retry delay in milliseconds.
        request_timeout: Request timeout in milliseconds.
    """

    port: int = Field(
        default=3000,
        ge=1,
        le=65535,
        description="HTTP server port",
    )
    log_level: str = Field(
        default="INFO",
        pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
        description="Logging level",
    )
    log_json: bool = Field(
        default=False,
        description="Use JSON format for logs",
    )
    log_file: str | None = Field(
        default=None,
        description="Optional log file path",
    )
    allowed_http_methods: list[str] = Field(
        default=["GET"],
        description="Allowed HTTP methods for tool generation",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum API retry attempts",
    )
    retry_delay: int = Field(
        default=1000,
        ge=100,
        le=30000,
        description="Retry delay in milliseconds",
    )
    request_timeout: int = Field(
        default=30000,
        ge=1000,
        le=300000,
        description="Request timeout in milliseconds",
    )

    model_config = {"extra": "ignore"}


class Config(BaseModel):
    """Main configuration container.

    Attributes:
        isilon: Isilon/PowerScale connection settings.
        server: Server settings.
    """

    isilon: IsilonConfig = Field(default_factory=IsilonConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)

    model_config = {"extra": "ignore"}


def load_config(env_file: str | None = None) -> Config:
    """Load configuration from environment variables.

    Args:
        env_file: Optional path to .env file.

    Returns:
        Validated Config object.

    Raises:
        ConfigurationError: If required configuration is missing.
    """
    # Load .env file if exists
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()

    logger.debug("Loading configuration from environment")

    try:
        # Build Isilon config
        isilon_config = IsilonConfig(
            host=os.getenv("ISILON_HOST", "localhost"),
            username=os.getenv("ISILON_USERNAME"),
            password=os.getenv("ISILON_PASSWORD"),
            local_spec_path=os.getenv("LOCAL_OPENAPI_SPEC_PATH"),
            tls_verify=os.getenv("TLS_VERIFY", "false").lower() == "true",
            port=int(os.getenv("ISILON_PORT", "8080")),
            use_https=os.getenv("ISILON_USE_HTTPS", "true").lower() == "true",
        )

        # Parse allowed methods
        allowed_methods_str = os.getenv(
            "ALLOWED_HTTP_METHODS", "GET,POST,PUT,DELETE,PATCH"
        )
        allowed_methods = [m.strip().upper() for m in allowed_methods_str.split(",")]

        # Build server config
        server_config = ServerConfig(
            port=int(os.getenv("HTTP_SERVER_PORT", "3000")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_json=os.getenv("LOG_JSON", "false").lower() == "true",
            log_file=os.getenv("LOG_FILE"),
            allowed_http_methods=allowed_methods,
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            retry_delay=int(os.getenv("RETRY_DELAY", "1000")),
            request_timeout=int(os.getenv("REQUEST_TIMEOUT", "30000")),
        )

        config = Config(
            isilon=isilon_config,
            server=server_config,
        )

        logger.info(
            "Configuration loaded successfully",
            extra={
                "spec_path": config.isilon.local_spec_path,
                "allowed_methods": config.server.allowed_http_methods,
            },
        )

        return config

    except ValueError as e:
        raise ConfigurationError(f"Invalid configuration: {e}") from e


def get_spec_path() -> str:
    """Get the OpenAPI spec path, with fallback to package default.

    Returns:
        Path to the OpenAPI spec file.

    Raises:
        EnvironmentVariableError: If no spec path is configured.
    """
    spec_path = os.getenv("LOCAL_OPENAPI_SPEC_PATH")

    if not spec_path:
        # Try to find openapi.json in the package directory
        package_dir = Path(__file__).parent.parent
        default_path = package_dir / "powerscale_9.7_comprehensive_openapi.json"
        if default_path.exists():
            return str(default_path)

        raise EnvironmentVariableError(
            "LOCAL_OPENAPI_SPEC_PATH",
            message="OpenAPI spec path not configured and default not found",
        )

    return spec_path
