from nameless_py.native.util.logging import logger
from nameless_py.native.util.server.data_manager import (
    ServerDataManager,
    ServerDataError,
    LoadServerParams,
    CreateServerParams,
)
from nameless_py.native.util.filesystem.symlink_manager import SymlinkUtil
from nameless_py.config import SERVER_DATA_DIR
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


class LoadOrCreateResult(TypedDict):
    server_name: str
    server_data: bytes
    password: str


class ServerDataInteraction:
    """Handles user interaction and configuration for server data management"""

    def __init__(self, server_data_manager: ServerDataManager):
        self.server_data_manager = server_data_manager
        self.salt_manager = self.server_data_manager.get_salt_manager()

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

    def _load(self, params: LoadServerParams) -> LoadOrCreateResult:
        try:
            default_path = os.path.join(
                self.server_data_manager.server_data_dir, "default"
            )
            real_name = os.path.basename(SymlinkUtil.read_link(default_path))
            password = params["password"]

            load_params: LoadServerParams = {
                "server_name": real_name,
                "password": password,
            }

            server_data = self.server_data_manager.decrypt(load_params)

            return {
                "server_data": server_data,
                "server_name": real_name,
                "password": password,
            }
        except Exception as e:
            logger.error(f"Failed to load server data: {e}")
            raise ServerDataError(f"Failed to load server data: {e}")

    def _create(self, params: CreateServerParams) -> LoadOrCreateResult:
        try:
            max_messages = params["max_messages"] or 2
            password = params["password"]
            server_name = params["server_name"]

            create_params: CreateServerParams = {
                "server_name": server_name,
                "password": password,
                "max_messages": max_messages,
            }
            server_data = self.server_data_manager.create(create_params)
            return {
                "server_data": server_data,
                "server_name": server_name,
                "password": password,
            }
        except Exception as e:
            logger.error(f"Failed to create server data: {e}")
            raise ServerDataError(f"Failed to create server data: {e}")

    def load_or_create(self, params: CreateServerParams) -> LoadOrCreateResult:
        try:
            # Create The Server Data Directory If It Doesn't Exist
            os.makedirs(self.server_data_manager.server_data_dir, exist_ok=True)
            default_path = os.path.join(
                self.server_data_manager.server_data_dir, "default"
            )

            # If The Default Server Data Exists, Load It
            if SymlinkUtil.exists(default_path):
                return self._load(params)
            else:
                # Otherwise, Create A New Server Data File
                return self._create(params)
        except OSError as e:
            logger.error(f"File system error: {e}")
            raise ServerSetupError(f"File system error: {e}")
        except Exception as e:
            logger.error(f"Failed to get server data: {e}")
            raise ServerDataError(f"Failed to get server data: {e}")

    def interactive_setup(self) -> LoadOrCreateResult:
        try:
            path_to_default_server_data = os.path.join(
                self.server_data_manager.server_data_dir, "default"
            )

            # If The Default Server Data Exists, Load It
            if SymlinkUtil.exists(path_to_default_server_data):
                # Ensure Server Is Loaded By Actual Name, Not The Link
                server_name = os.path.basename(
                    SymlinkUtil.read_link(path_to_default_server_data)
                )

                # Prompt For Password
                password = getpass.getpass(f"Decryption Key for {server_name}: ")
                try:
                    # Load The Server Data
                    load_params: LoadServerParams = {
                        "server_name": server_name,
                        "password": password,
                    }
                    return self._load(load_params)
                except Exception as e:
                    raise ServerLoadError(f"Failed to load existing server: {e}")
            else:
                # Otherwise, Prompt For New Server Configuration
                logger.warning(
                    f"No Server Configuration Found At {path_to_default_server_data}"
                )
                while True:
                    if self._prompt_for_new_server_confirmation():
                        try:
                            # Prompt For Server Name
                            server_name = self._prompt_for_server_name()

                            # Prompt For Maximum Number Of Messages
                            max_messages = self._prompt_for_max_messages()

                            # Prompt For Password
                            password = getpass.getpass(
                                "Enter a password to encrypt the server data: "
                            )

                            # Create The Server Data
                            create_params: CreateServerParams = {
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
