#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom logger with colored output for terminal and file logging
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

try:
    # colorama is only needed on legacy Windows consoles (it translates ANSI
    # to Win32 calls). If present we use it; otherwise we emit raw ANSI escapes,
    # which every Linux/macOS terminal -- and modern Windows Terminal -- render
    # natively. No hard dependency either way.
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback: real ANSI SGR codes (colorama absent). Previously these were
    # empty strings, which is why output came out monochrome on Linux/macOS.
    class Fore:
        BLACK = '\033[30m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
    class Style:
        BRIGHT = '\033[1m'
        RESET_ALL = '\033[0m'


# --- color mode ------------------------------------------------------------
# 'auto' -> color only when stdout is a TTY (and NO_COLOR unset); 'always' and
# 'never' force it on/off. --color wires this via set_color_mode(). Read at emit
# time so a mode set before the first log line takes effect immediately.
_COLOR_MODE = 'auto'


def set_color_mode(mode: str) -> None:
    """Set global color mode: 'auto' | 'always' | 'never'."""
    global _COLOR_MODE
    _COLOR_MODE = mode


def color_enabled() -> bool:
    """Whether ANSI color should be emitted right now."""
    if _COLOR_MODE == 'always':
        return True
    if _COLOR_MODE == 'never':
        return False
    # auto
    if os.environ.get('NO_COLOR') is not None:
        return False
    if os.environ.get('FORCE_COLOR') is not None:
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output"""

    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.CYAN,               # teal -- the bulk of output
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'SUCCESS': Fore.GREEN,           # Custom level
        'CRITICAL': Fore.RED + Style.BRIGHT,  # bright red
    }

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        # Handle custom SUCCESS level
        if not hasattr(record, 'levelname'):
            record.levelname = 'INFO'

        # Get color for level
        if self.use_colors and color_enabled():
            color = self.COLORS.get(record.levelname, Fore.WHITE)
            reset = Style.RESET_ALL
        else:
            color = ''
            reset = ''

        # Format: [TIME] [LEVEL] Message
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        formatted = f"{color}[{timestamp}] [{record.levelname}] {record.getMessage()}{reset}"

        return formatted


class ColoredLogger:
    """
    Logger with colored console output and optional file logging.
    Replaces standard logging to avoid duplicate output.
    """

    # Custom log level for SUCCESS (between INFO and WARNING)
    SUCCESS_LEVEL = 25

    def __init__(self,
                 name: str = "BitrixPentest",
                 level: int = logging.INFO,
                 log_file: Optional[str] = None,
                 use_colors: bool = True):
        """
        Initialize logger

        Args:
            name: Logger name (used for file logging only)
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path to write logs
            use_colors: Whether to use colored output
        """
        self.name = name
        self.level = level
        # Native ANSI works without colorama; color_enabled() decides at emit
        # time whether to actually paint (TTY / --color / NO_COLOR).
        self.use_colors = use_colors
        self.log_file = log_file

        # Add custom SUCCESS level if not exists
        if not hasattr(logging, 'SUCCESS'):
            logging.addLevelName(self.SUCCESS_LEVEL, 'SUCCESS')
            logging.SUCCESS = self.SUCCESS_LEVEL

        # File logging setup (optional)
        self.file_logger = None
        if log_file:
            self._setup_file_logging()

    def _setup_file_logging(self):
        """Setup file logging separately"""
        self.file_logger = logging.getLogger(f"{self.name}_file")
        self.file_logger.setLevel(logging.DEBUG)
        self.file_logger.propagate = False

        try:
            handler = logging.FileHandler(self.log_file, encoding='utf-8', mode='a')
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.file_logger.addHandler(handler)
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}")
            self.file_logger = None

    def _log(self, level: str, message: str, std_level: int):
        """
        Internal log method

        Args:
            level: Display level string
            message: Message to log
            std_level: Standard logging level for file
        """
        # Console output with colors (whole line colored by severity:
        # critical/error -> red, success -> green, warning -> yellow).
        if self.use_colors and color_enabled():
            colors = {
                'DEBUG': Fore.BLUE,
                'INFO': Fore.WHITE,
                'WARNING': Fore.YELLOW,
                'ERROR': Fore.RED,
                'SUCCESS': Fore.GREEN,
                'CRITICAL': Fore.RED + Style.BRIGHT,   # critical -> bright red
            }
            color = colors.get(level, Fore.WHITE)
            reset = Style.RESET_ALL
        else:
            color = ''
            reset = ''

        # Keep the [time] [LEVEL] prefix attached to the text: any leading
        # newlines in the message become real blank lines emitted BEFORE the
        # prefix, instead of stranding the prefix on its own line above an
        # unprefixed remainder.
        lead = len(message) - len(message.lstrip('\n'))
        blanks = '\n' * lead
        body = message[lead:]

        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{blanks}{color}[{timestamp}] [{level}] {body}{reset}")

        # File logging
        if self.file_logger:
            try:
                # Map custom levels to standard
                level_map = {
                    'SUCCESS': logging.INFO,
                }
                file_level = level_map.get(level, std_level)
                self.file_logger.log(file_level, message)
            except Exception:
                pass

    def debug(self, message: str):
        """Log debug message"""
        if self.level <= logging.DEBUG:
            self._log('DEBUG', message, logging.DEBUG)

    def info(self, message: str):
        """Log info message"""
        if self.level <= logging.INFO:
            self._log('INFO', message, logging.INFO)

    def warning(self, message: str):
        """Log warning message"""
        if self.level <= logging.WARNING:
            self._log('WARNING', message, logging.WARNING)

    def error(self, message: str):
        """Log error message"""
        if self.level <= logging.ERROR:
            self._log('ERROR', message, logging.ERROR)

    def success(self, message: str):
        """Log success message (custom level)"""
        if self.level <= self.SUCCESS_LEVEL:
            self._log('SUCCESS', message, logging.INFO)

    def critical(self, message: str):
        """Log critical message"""
        if self.level <= logging.CRITICAL:
            self._log('CRITICAL', message, logging.CRITICAL)

    def exception(self, message: str):
        """Log exception with traceback"""
        import traceback
        self.error(message)
        self.debug(traceback.format_exc())


# Simple test
if __name__ == "__main__":
    log = ColoredLogger(level=logging.DEBUG, log_file="test.log")
    print("Testing logger levels:")
    log.debug("Debug message")
    log.info("Info message")
    log.success("Success message")
    log.warning("Warning message")
    log.error("Error message")
    log.critical("Critical message")
    print(f"\nLog file created: test.log")
