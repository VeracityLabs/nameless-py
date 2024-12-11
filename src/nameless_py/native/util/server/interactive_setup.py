from nameless_py.native.util.logging import logger
from nameless_py.native.util.server.data_manager import (
    ServerDataManager,
    ServerDataError,
    DecryptServerParams,
    CreateServerParams,
)
from nameless_py.native.util.encryption.salt_manager import SaltManager
from nameless_py.native.util.filesystem.symlink_manager import SymlinkUtil
from nameless_py.config import SERVER_DATA_DIR, SALT_FILE_PATH
from typing import Optional, TypedDict
import os
import sys
import getpass

MIN_MAX_MESSAGES = 2
MAX_SERVER_NAME_LENGTH = 32


###
# Exceptions
###


# Base exception class for user input-related errors
class UserInputError(Exception):
    """Base exception for all user input related errors"""

    pass


class ServerNameError(UserInputError):
    """Raised when server name validation fails"""

    pass


class MaxMessagesError(UserInputError):
    """Raised when max messages validation fails"""

    pass


class UserConfirmationError(UserInputError):
    """Raised when user confirmation input is invalid"""

    pass


class ServerSetupError(Exception):
    """Raised when server setup process fails"""

    pass


class ServerLoadError(ServerSetupError):
    """Raised when loading existing server configuration fails"""

    pass


class ServerCreationError(ServerSetupError):
    """Raised when creating new server configuration fails"""

    pass


###
# Parameters for Server Data Interaction
###


class LoadOrCreateParams(TypedDict):
    server_data_dir: str
    server_name: str
    password: str
    max_messages: int


class LoadOrCreateResult(TypedDict):
    server_data_dir: str
    server_name: str
    server_data: bytes
    password: str


class InteractiveSetupParams(TypedDict):
    server_data_dir: str


class ServerDataInteraction:
    """Handles user interaction and configuration for server data management"""

    def __init__(self):
        self.server_data_manager = ServerDataManager()
        self.salt_manager = SaltManager(SALT_FILE_PATH)

    @staticmethod
    def _prompt_for_server_name() -> str:
        while True:
            server_name = input(
                f"Enter a name for the server (up to {MAX_SERVER_NAME_LENGTH} ASCII characters): "
            ).strip()
            if len(server_name) <= MAX_SERVER_NAME_LENGTH and all(
                ord(c) < 128 for c in server_name
            ):
                return server_name
            else:
                logger.warning(
                    f"The server name must be up to {MAX_SERVER_NAME_LENGTH} ASCII characters."
                )
                raise ServerNameError("Invalid server name format")

    @staticmethod
    def _prompt_for_max_messages() -> int:
        while True:
            try:
                max_messages = int(
                    input(
                        f"Enter the maximum number of messages (minimum of {MIN_MAX_MESSAGES}): "
                    ).strip()
                )
                if max_messages >= MIN_MAX_MESSAGES:
                    return max_messages
                else:
                    logger.warning(
                        f"Please enter a number greater than or equal to {MIN_MAX_MESSAGES}."
                    )
                    raise MaxMessagesError(f"Value must be >= {MIN_MAX_MESSAGES}")
            except ValueError:
                logger.warning("Invalid input. Please enter a valid number.")
                raise MaxMessagesError("Invalid numeric input")

    @staticmethod
    def _prompt_for_new_server_confirmation() -> bool:
        while True:
            create_new = (
                input("Would you like to create a new server configuration? (y/n): ")
                .strip()
                .lower()
            )
            if create_new == "y":
                return True
            elif create_new == "n":
                return False
            else:
                logger.warning("Invalid input. Please enter 'y' or 'n'.")
                raise UserConfirmationError("Invalid confirmation input")

    def _load(self, params: LoadOrCreateParams) -> LoadOrCreateResult:
        try:
            server_data_dir = params["server_data_dir"]
            default_path = os.path.join(server_data_dir, "default")
            name = os.path.basename(SymlinkUtil.read_link(default_path))

            salt_manager = SaltManager(SALT_FILE_PATH)
            salt = salt_manager.fetch_or_create()

            password = params["password"]

            decrypt_params: DecryptServerParams = {
                "server_data_dir": server_data_dir,
                "encrypted_name": name,
                "salt": salt,
                "password": params["password"],
            }

            server_data = self.server_data_manager.decrypt(decrypt_params)

            return {
                "server_data": server_data,
                "server_name": name,
                "server_data_dir": server_data_dir,
                "password": password,
            }
        except Exception as e:
            logger.error(f"Failed to load server data: {e}")
            raise ServerDataError(f"Failed to load server data: {e}")

    def _create(self, params: LoadOrCreateParams) -> LoadOrCreateResult:
        try:
            server_data_dir = params["server_data_dir"]

            salt_manager = SaltManager(SALT_FILE_PATH)
            salt = salt_manager.fetch_or_create()

            max_messages = params["max_messages"] or 2
            password = params["password"]
            server_name = params["server_name"]

            create_params: CreateServerParams = {
                "server_data_dir": server_data_dir,
                "server_name": server_name,
                "salt": salt,
                "password": password,
                "max_messages": max_messages,
            }
            server_data = self.server_data_manager.create(create_params)
            return {
                "server_data": server_data,
                "server_name": server_name,
                "server_data_dir": server_data_dir,
                "password": password,
            }
        except Exception as e:
            logger.error(f"Failed to create server data: {e}")
            raise ServerDataError(f"Failed to create server data: {e}")

    def load_or_create(self, params: LoadOrCreateParams) -> LoadOrCreateResult:
        try:
            server_data_dir = params["server_data_dir"]

            os.makedirs(server_data_dir, exist_ok=True)
            default_path = os.path.join(server_data_dir, "default")

            if SymlinkUtil.exists(default_path):
                return self._load(params)
            else:
                return self._create(params)
        except OSError as e:
            logger.error(f"File system error: {e}")
            raise ServerSetupError(f"File system error: {e}")
        except Exception as e:
            logger.error(f"Failed to get server data: {e}")
            raise ServerDataError(f"Failed to get server data: {e}")

    def interactive_setup(
        self,
        params: InteractiveSetupParams,
    ) -> LoadOrCreateResult:
        try:
            server_data_dir = params["server_data_dir"]
            path_to_default_server_data = os.path.join(server_data_dir, "default")

            if SymlinkUtil.exists(path_to_default_server_data):
                name = os.path.basename(
                    SymlinkUtil.read_link(path_to_default_server_data)
                )
                password = getpass.getpass(f"Decryption Key for {name}: ")
                load_params: LoadOrCreateParams = {
                    "server_data_dir": params["server_data_dir"],
                    "password": password,
                    "server_name": name,
                    "max_messages": 2,
                }
                try:
                    return self._load(load_params)
                except Exception as e:
                    raise ServerLoadError(f"Failed to load existing server: {e}")
            else:
                logger.warning(
                    f"No server configuration found at {path_to_default_server_data}"
                )
                while True:
                    if self._prompt_for_new_server_confirmation():
                        try:
                            server_name = self._prompt_for_server_name()
                            max_messages = self._prompt_for_max_messages()
                            password = getpass.getpass(
                                "Enter a password to encrypt the server data: "
                            )
                            create_params: LoadOrCreateParams = {
                                "server_data_dir": params["server_data_dir"],
                                "password": password,
                                "server_name": server_name,
                                "max_messages": max_messages,
                            }
                            return self.load_or_create(create_params)
                        except Exception as e:
                            raise ServerCreationError(
                                f"Failed to create new server: {e}"
                            )
                    else:
                        logger.info("Server data file creation aborted by user.")
                        sys.exit("Server data file creation aborted by user.")
        except UserInputError as e:
            logger.error(f"User input error: {e}")
            raise
        except ServerSetupError as e:
            logger.error(f"Server setup error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise ServerDataError(f"Failed to get server data: {e}")
