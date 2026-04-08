"""
Logger utility for Vuln_Scanner_AG.
Provides a configured logger with colored output for different log levels.
"""
import logging
import sys
from colorama import init, Fore, Style


init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatting with colors to highlight log severity levels."""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT
    }

    def format(self, record):
        log_message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{log_message}{Style.RESET_ALL}"

def setup_logger(name: str = "VulnScanner", level: int = logging.INFO) -> logging.Logger:
    """
    Create and configure a PEP 8 compliant logger instance.

    Args:
        name (str): The name of the logger instance.
        level (int): The logging severity level.

    Returns:
        logging.Logger: The configured logger instance.
    """
    logger_instance = logging.getLogger(name)
    logger_instance.setLevel(level)


    if not logger_instance.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        formatter = ColoredFormatter(
            '%(asctime)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        logger_instance.addHandler(console_handler)

    return logger_instance


logger = setup_logger()
