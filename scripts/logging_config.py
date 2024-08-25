import logging
import colorlog
import os
# Define the custom logging level for success
SUCCESS = 35
logging.SUCCESS = SUCCESS
logging.addLevelName(SUCCESS, "SUCCESS")

class CustomLogger(logging.Logger):
    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kwargs)

log = CustomLogger(__name__)
log.setLevel(logging.INFO)  # Set the default level

# Define log formats with color and include only time in timestamp
formatter = colorlog.ColoredFormatter(
    '%(log_color)s[%(asctime)s] - [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'WARNING': 'yellow',
        'INFO': 'blue',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
        'SUCCESS': 'green'
    },
    secondary_log_colors={},
    style='%'
)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

# Ensure the directory exists
nmb_log_dir = os.path.join("logs", "nmb")
os.makedirs(nmb_log_dir, exist_ok=True)

# File Handler
nmb_log_file_path = os.path.join(nmb_log_dir, 'NMB_output.log')
file_handler = logging.FileHandler(nmb_log_file_path) 
file_handler.setFormatter(formatter)
log.addHandler(file_handler)
