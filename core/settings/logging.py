import logging.config
from .common import *

LOG_LEVEL = config("LOG_LEVEL", default="INFO")

log_config = {
    "version": 1,
    "handlers": {
        "console": {
            "class": "autoutils.log.ColorfulStreamHandler",
            "level": LOG_LEVEL,
            "file_depth": 2,
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "DEBUG",
        },
    },
}
logging.config.dictConfig(log_config)
