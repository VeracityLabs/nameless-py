from nameless_py.native.util.logging import logger
from nameless_py.native.util.encryption.data_encryption import (
    AESDataEncryption,
    DecryptionError,
)
from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer
from nameless_py.native.util.filesystem.symlink_manager import SymlinkUtil, SymlinkError
from nameless_py.native.util.encryption.salt_manager import SaltManager
from nameless_py.config import SALT_FILE_PATH, SERVER_DATA_DIR
from typing import Optional, TypedDict
import os
import base64
import random
import string


###
# Exceptions
###


# Base exception class for server data-related errors
class ServerDataError(Exception):
    pass


# Raised when server data file operations fail
class ServerDataFileError(ServerDataError):
    pass


# Raised when server data creation fails
class ServerDataCreationError(ServerDataError):
    pass


# Raised when server data saving fails
class ServerDataSaveError(ServerDataError):
    pass


###
# Parameters for Server Data Management Functions
###


class LoadServerParams(TypedDict):
    server_name: str
    password: str


class CreateServerParams(TypedDict):
    server_name: str
    password: str
    max_messages: int


class SaveServerParams(TypedDict):
    server_name: str
    server_data: bytes
    password: str


class ServerDataManager:
    def __init__(
        self,
        server_data_dir: Optional[str] = None,
        salt_file_path: Optional[str] = None,
    ):
        self.encryption = AESDataEncryption()
        self.salt_manager = SaltManager(salt_file_path or SALT_FILE_PATH)
        self.server_data_dir = server_data_dir or SERVER_DATA_DIR

    def get_salt_manager(self) -> SaltManager:
        return self.salt_manager

    @staticmethod
    def generate_server_name() -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=16))

    def exists(self, server_name: str) -> bool:
        return os.path.exists(os.path.join(self.server_data_dir, server_name))

    def create_default_if_not_exists(self, params: CreateServerParams) -> bytes:
        # Create If Default Not Exists
        if not self.exists("default"):
            data = self.create(params)
            actual_server_name = params["server_name"]
            self.set_server_as_default(actual_server_name)
            return data

        # Decrypt If Default Exists
        decryption_params: LoadServerParams = {
            "server_name": "default",
            "password": params["password"],
        }
        return self.decrypt(decryption_params)

    def set_server_as_default(self, server_name: str) -> None:
        try:
            default_path = os.path.join(self.server_data_dir, "default")
            target_path = os.path.join(self.server_data_dir, server_name)

            if not os.path.exists(target_path):
                raise ServerDataError(f"Server data file not found: {target_path}")

            try:
                SymlinkUtil._create_symlink(target_path, default_path)
            except SymlinkError as e:
                raise ServerDataError(f"Failed to create default symlink: {e}")

        except KeyError as e:
            raise ServerDataError(f"Missing required parameter: {e}")
        except Exception as e:
            logger.error(f"Failed to set server as default: {e}")
            raise ServerDataError(f"Failed to set server as default: {e}")

    def decrypt(self, params: LoadServerParams) -> bytes:
        try:
            server_data_path = os.path.join(self.server_data_dir, params["server_name"])

            # Resolve symlink if it exists
            if SymlinkUtil.exists(server_data_path):
                server_data_path = SymlinkUtil.read_link(server_data_path)

            with open(server_data_path, "rb") as f:
                encrypted_data = f.read()
            return self.encryption.decrypt_data(
                {
                    "encrypted_data": encrypted_data,
                    "password": params["password"],
                    "salt": self.salt_manager.fetch(),
                }
            )
        except FileNotFoundError:
            raise ServerDataFileError(f"Server data file not found: {server_data_path}")
        except DecryptionError as e:
            raise DecryptionError(f"Failed to decrypt server data: {e}")
        except Exception as e:
            logger.error(f"Failed to decrypt server data: {e}")
            raise ServerDataError(f"Failed to decrypt server data: {e}")

    def create(self, params: CreateServerParams) -> bytes:
        try:
            server_data = NativeMonolithicIssuer(
                params["max_messages"]
            ).issuer.export_cbor()
            encrypted_name = base64.b64encode(
                params["server_name"].encode("ascii")
            ).decode("ascii")
            password = params["password"]
            save_params: SaveServerParams = {
                "server_name": encrypted_name,
                "server_data": server_data,
                "password": password,
            }
            self.save(save_params)
            return server_data
        except Exception as e:
            logger.error(f"Failed to create new server data: {e}")
            raise ServerDataCreationError(f"Failed to create new server data: {e}")

    def save(self, params: SaveServerParams) -> None:
        try:
            if params["server_name"] == "default":
                raise ServerDataSaveError("Cannot Save Server Data With Name 'default'")

            if not os.path.exists(self.server_data_dir):
                os.makedirs(self.server_data_dir)

            data = params["server_data"]
            password = params["password"]
            salt = self.salt_manager.fetch()
            encrypted_data = self.encryption.encrypt_data(
                {
                    "data": data,
                    "password": password,
                    "salt": salt,
                }
            )
            server_data_path = os.path.join(self.server_data_dir, params["server_name"])
            with open(server_data_path, "wb") as f:
                f.write(encrypted_data)

            return None
        except OSError as e:
            raise ServerDataSaveError(f"Failed to save server data: {e}")
        except Exception as e:
            logger.error(f"Failed to save server data: {e}")
            raise ServerDataSaveError(f"Failed to save server data: {e}")
