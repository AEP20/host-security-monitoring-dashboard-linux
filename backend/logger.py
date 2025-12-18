import logging
import os

LOG_PATH = "/var/log/hids/app.log"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger("hids")
logger.setLevel(LOG_LEVEL)

fh = logging.FileHandler(LOG_PATH)
fh.setLevel(LOG_LEVEL)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
)
fh.setFormatter(formatter)

# duplicate handler eklenmesin diye
if not logger.handlers:
    logger.addHandler(fh)
