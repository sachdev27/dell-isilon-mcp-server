"""Logging configuration for Isilon MCP Server.

This module provides structured logging with configurable formatters,
handlers, and log levels. It supports both console and file logging
with JSON formatting option for production environments.

Example:
    >>> from isilon_mcp.logging_config import setup_logging, get_logger
    >>> setup_logging(log_level="DEBUG", json_format=True)
    >>> logger = get_logger(__name__)
    >>> logger.info("Server started", extra={"port": 3000})
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

# Define custom log levels
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

# Package logger
PACKAGE_NAME = "isilon_mcp"


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging in production.

    Outputs log records as JSON objects with consistent structure
    for easy parsing by log aggregation systems.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: The log record to format.

        Returns:
            JSON-formatted log string.
        """
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add location info
        if record.pathname:
            log_data["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields (excluding standard LogRecord attributes)
        standard_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "taskName",
            "message",
        }
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                if "extra" not in log_data:
                    log_data["extra"] = {}
                log_data["extra"][key] = value

        return json.dumps(log_data, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for development.

    Uses ANSI color codes to highlight different log levels
    for easier reading during development.
    """

    # ANSI color codes
    COLORS = {
        "TRACE": "\033[90m",  # Dark gray
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        use_colors: bool = True,
    ) -> None:
        """Initialize the formatter.

        Args:
            fmt: Log message format string.
            datefmt: Date format string.
            use_colors: Whether to use ANSI colors.
        """
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional colors.

        Args:
            record: The log record to format.

        Returns:
            Formatted log string.
        """
        # Save original values
        original_levelname = record.levelname
        original_msg = record.msg

        if self.use_colors:
            color = self.COLORS.get(record.levelname, "")
            record.levelname = f"{color}{self.BOLD}{record.levelname:8}{self.RESET}"
            # Color the message based on level
            if record.levelno >= logging.ERROR:
                record.msg = f"{self.COLORS['ERROR']}{record.msg}{self.RESET}"
            elif record.levelno >= logging.WARNING:
                record.msg = f"{self.COLORS['WARNING']}{record.msg}{self.RESET}"

        result = super().format(record)

        # Restore original values
        record.levelname = original_levelname
        record.msg = original_msg

        return result


class RequestContextFilter(logging.Filter):
    """Filter that adds request context to log records.

    This filter can be used to add contextual information
    like request IDs or user information to all log records.
    """

    def __init__(self, name: str = "", context: dict[str, Any] | None = None) -> None:
        """Initialize the filter.

        Args:
            name: Logger name to filter.
            context: Default context to add to all records.
        """
        super().__init__(name)
        self.context = context or {}

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context to log record.

        Args:
            record: The log record to modify.

        Returns:
            True to include the record.
        """
        for key, value in self.context.items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds extra context to all log messages.

    Example:
        >>> logger = LoggerAdapter(get_logger(__name__), {"host": "powerscale.example.com"})
        >>> logger.info("Connected")  # Includes host in extra
    """

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Process log message and add extra context.

        Args:
            msg: The log message.
            kwargs: Keyword arguments for logging.

        Returns:
            Tuple of (message, kwargs) with extra context merged.
        """
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging(
    log_level: str = "INFO",
    json_format: bool = False,
    log_file: str | None = None,
) -> None:
    """Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: Use JSON format for production logging.
        log_file: Optional file path for file logging.
    """
    # Get the root package logger
    logger = logging.getLogger(PACKAGE_NAME)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Create console handler (stderr for stdio compatibility)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG)

    # Choose formatter based on environment
    if json_format:
        formatter: logging.Formatter = StructuredFormatter()
    else:
        formatter = ColoredFormatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Add file handler if requested
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)

    # Don't propagate to root logger
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Get a logger for the given module.

    Args:
        name: Module name (typically __name__).

    Returns:
        Logger instance.
    """
    # Ensure it's under our package namespace
    if not name.startswith(PACKAGE_NAME):
        name = f"{PACKAGE_NAME}.{name}"
    return logging.getLogger(name)
