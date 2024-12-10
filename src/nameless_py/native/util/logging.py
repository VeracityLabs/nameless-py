from rich.logging import RichHandler
import logging

# Constants
LOGGING_FORMAT = "%(message)s"
LOGGING_DATEFMT = "[%X]"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format=LOGGING_FORMAT,
    datefmt=LOGGING_DATEFMT,
    handlers=[RichHandler()],
)

logger = logging.getLogger(__name__)
