import logging
import sys
from pathlib import Path
from typing import Optional, Union

from detectiq.globals import DEFAULT_DIRS


class LoggerConfig:
    """Configuration class for logging setup."""

    DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    DEFAULT_LEVEL = logging.INFO


def setup_logger(
    name: str,
    level: Optional[Union[int, str]] = None,
    log_file: Optional[Union[str, Path]] = None,
    format_string: Optional[str] = None,
    date_format: Optional[str] = None,
) -> logging.Logger:
    """
    Set up and configure a logger instance.

    Args:
        name: Name of the logger
        level: Logging level (default: INFO)
        log_file: Optional path to log file
        format_string: Optional custom format string
        date_format: Optional custom date format

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)

    # Set logging level
    log_level = level if level is not None else logging.getLevelName(LoggerConfig.DEFAULT_LEVEL)
    if isinstance(log_level, str):
        log_level = logging.getLevelName(log_level.upper())
    logger.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        format_string or LoggerConfig.DEFAULT_FORMAT, date_format or LoggerConfig.DEFAULT_DATE_FORMAT
    )

    # Add console handler if none exists
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Add file handler if log file is specified
    if log_file:
        log_path = Path(log_file) if isinstance(log_file, str) else log_file

        # If path is relative, make it relative to the default log directory
        if not log_path.is_absolute():
            log_path = DEFAULT_DIRS.LOG_DIR / log_path

        # Ensure log directory exists
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(
    name: str, level: Optional[Union[int, str]] = None, log_file: Optional[Union[str, Path]] = None
) -> logging.Logger:
    """
    Get or create a logger with the specified configuration.

    Args:
        name: Name of the logger
        level: Optional logging level
        log_file: Optional path to log file

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if logger hasn't been configured yet
    if not logger.handlers:
        return setup_logger(name, level, log_file)

    return logger
