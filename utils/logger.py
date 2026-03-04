"""
Logger Utility
Provides colored console output and file logging.
"""
import logging
import sys
from colorama import Fore, Style, init

init(autoreset=True)

_loggers = {}

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.WHITE,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}"


def get_logger(verbose: bool = False, quiet: bool = False, name: str = "vulnscan") -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    if quiet:
        logger.setLevel(logging.ERROR)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColoredFormatter("%(message)s"))
        logger.addHandler(handler)

    _loggers[name] = logger
    return logger
