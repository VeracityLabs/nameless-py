import os

SERVER_DATA_DIR: str = os.path.join(os.path.expanduser("~"), ".veracity_server")
SALT_FILE_PATH: str = os.path.join(SERVER_DATA_DIR, "salt", "saltfile")
CREDENTIALS_DIR: str = os.path.expanduser("~/.veracity_credentials")
