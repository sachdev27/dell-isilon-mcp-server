"""Custom exceptions for Isilon MCP Server.

This module defines a hierarchy of exceptions for precise error handling
throughout the application. All exceptions inherit from a base exception
class to allow catching all Isilon-related errors with a single handler.

Example:
    >>> try:
    ...     await client.execute_operation("/platform/1/cluster/config", "GET")
    ... except IsilonAPIError as e:
    ...     logger.error(f"API call failed: {e}")
    ... except IsilonMCPError as e:
    ...     logger.error(f"MCP operation failed: {e}")
"""

from typing import Any


class IsilonMCPError(Exception):
    """Base exception for all Isilon MCP Server errors.

    All custom exceptions in this package inherit from this class,
    allowing you to catch any Isilon-related error with a single
    except clause.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary with additional error context.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error description.
            details: Optional dictionary with additional error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the exception."""
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary with error information.
        """
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(IsilonMCPError):
    """Raised when server configuration is invalid or missing.

    This exception is raised during server startup when required
    configuration values are missing or invalid.

    Example:
        >>> if not config.local_spec_path:
        ...     raise ConfigurationError(
        ...         "OpenAPI spec path is required",
        ...         details={"env_var": "LOCAL_OPENAPI_SPEC_PATH"}
        ...     )
    """

    pass


class EnvironmentVariableError(ConfigurationError):
    """Raised when a required environment variable is missing or invalid.

    Attributes:
        variable_name: Name of the missing/invalid environment variable.
    """

    def __init__(
        self,
        variable_name: str,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            variable_name: Name of the missing/invalid environment variable.
            message: Optional custom message.
            details: Optional additional details.
        """
        default_message = (
            f"Environment variable '{variable_name}' is missing or invalid"
        )
        super().__init__(message or default_message, details)
        self.variable_name = variable_name


# =============================================================================
# OpenAPI Errors
# =============================================================================


class OpenAPILoadError(IsilonMCPError):
    """Raised when the OpenAPI spec cannot be loaded.

    Attributes:
        spec_path: Path to the OpenAPI spec file.
    """

    def __init__(
        self,
        spec_path: str,
        original_error: Exception | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            spec_path: Path to the OpenAPI spec file.
            original_error: The underlying exception.
            message: Optional custom message.
        """
        default_message = f"Failed to load OpenAPI spec from: {spec_path}"
        if original_error:
            default_message += f" - {original_error}"
        super().__init__(message or default_message)
        self.spec_path = spec_path
        self.original_error = original_error


class OpenAPIParseError(IsilonMCPError):
    """Raised when the OpenAPI spec cannot be parsed.

    Attributes:
        spec_path: Path to the OpenAPI spec file.
    """

    def __init__(
        self,
        spec_path: str,
        original_error: Exception | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            spec_path: Path to the OpenAPI spec file.
            original_error: The underlying exception.
            message: Optional custom message.
        """
        default_message = f"Failed to parse OpenAPI spec: {spec_path}"
        if original_error:
            default_message += f" - {original_error}"
        super().__init__(message or default_message)
        self.spec_path = spec_path
        self.original_error = original_error


# =============================================================================
# API Errors
# =============================================================================


class IsilonAPIError(IsilonMCPError):
    """Base class for Isilon API errors.

    Attributes:
        status_code: HTTP status code from the API response.
        response_body: Raw response body.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error description.
            status_code: HTTP status code.
            response_body: Raw response body.
            details: Additional error details.
        """
        super().__init__(message, details)
        self.status_code = status_code
        self.response_body = response_body


class AuthenticationError(IsilonAPIError):
    """Raised when authentication fails.

    This typically happens when:
    - Username or password is invalid
    - The account is locked
    - RBAC permissions are insufficient
    """

    def __init__(
        self,
        message: str = "Authentication failed - check your credentials",
        status_code: int | None = 401,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message, status_code, details=details)


class AuthorizationError(IsilonAPIError):
    """Raised when authorization fails (403 Forbidden).

    This happens when the user doesn't have permission for the operation.
    """

    def __init__(
        self,
        message: str = "Access denied - insufficient permissions",
        status_code: int | None = 403,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message, status_code, details=details)


class ConnectionError(IsilonAPIError):
    """Raised when connection to Isilon fails.

    This typically happens when:
    - The host is unreachable
    - The port is wrong
    - TLS/SSL certificate verification fails
    """

    def __init__(
        self,
        host: str,
        original_error: Exception | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            host: The Isilon host that couldn't be reached.
            original_error: The underlying connection error.
            message: Optional custom message.
        """
        default_message = f"Failed to connect to PowerScale at {host}"
        if original_error:
            default_message += f" - {original_error}"
        super().__init__(message or default_message)
        self.host = host
        self.original_error = original_error


class APIResponseError(IsilonAPIError):
    """Raised when the API returns an error response.

    Attributes:
        error_code: Isilon-specific error code.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        error_code: str | None = None,
        response_body: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error description.
            status_code: HTTP status code.
            error_code: Isilon-specific error code.
            response_body: Raw response body.
            details: Additional error details.
        """
        super().__init__(message, status_code, response_body, details)
        self.error_code = error_code


class RateLimitError(IsilonAPIError):
    """Raised when API rate limit is exceeded.

    Attributes:
        retry_after: Seconds to wait before retrying.
    """

    def __init__(
        self,
        retry_after: int | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            retry_after: Seconds to wait before retrying.
            message: Optional custom message.
        """
        default_message = "API rate limit exceeded"
        if retry_after:
            default_message += f" - retry after {retry_after} seconds"
        super().__init__(message or default_message, status_code=429)
        self.retry_after = retry_after


class ResourceNotFoundError(IsilonAPIError):
    """Raised when a requested resource is not found (404).

    Attributes:
        resource_path: Path to the resource that wasn't found.
    """

    def __init__(
        self,
        resource_path: str,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            resource_path: Path to the resource.
            message: Optional custom message.
        """
        default_message = f"Resource not found: {resource_path}"
        super().__init__(message or default_message, status_code=404)
        self.resource_path = resource_path


# =============================================================================
# Tool Errors
# =============================================================================


class ToolNotFoundError(IsilonMCPError):
    """Raised when a requested tool doesn't exist.

    Attributes:
        tool_name: Name of the tool that wasn't found.
    """

    def __init__(
        self,
        tool_name: str,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            tool_name: Name of the tool that wasn't found.
            message: Optional custom message.
        """
        default_message = f"Tool not found: {tool_name}"
        super().__init__(message or default_message)
        self.tool_name = tool_name


class InvalidToolArgumentsError(IsilonMCPError):
    """Raised when tool arguments are invalid or missing.

    Attributes:
        tool_name: Name of the tool.
        missing_args: List of missing required arguments.
        invalid_args: Dictionary of invalid arguments with reasons.
    """

    def __init__(
        self,
        tool_name: str,
        missing_args: list[str] | None = None,
        invalid_args: dict[str, str] | None = None,
        message: str | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            tool_name: Name of the tool.
            missing_args: List of missing required arguments.
            invalid_args: Dictionary of invalid arguments with reasons.
            message: Optional custom message.
        """
        parts = [f"Invalid arguments for tool: {tool_name}"]
        if missing_args:
            parts.append(f"Missing: {', '.join(missing_args)}")
        if invalid_args:
            invalid_str = ", ".join(f"{k}: {v}" for k, v in invalid_args.items())
            parts.append(f"Invalid: {invalid_str}")

        super().__init__(message or " - ".join(parts))
        self.tool_name = tool_name
        self.missing_args = missing_args or []
        self.invalid_args = invalid_args or {}


class ToolExecutionError(IsilonMCPError):
    """Raised when tool execution fails.

    Attributes:
        tool_name: Name of the tool that failed.
    """

    def __init__(
        self,
        tool_name: str,
        original_error: Exception | None = None,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            tool_name: Name of the tool that failed.
            original_error: The underlying exception.
            message: Optional custom message.
            details: Additional error details.
        """
        default_message = f"Tool execution failed: {tool_name}"
        if original_error:
            default_message += f" - {original_error}"
        super().__init__(message or default_message, details)
        self.tool_name = tool_name
        self.original_error = original_error
