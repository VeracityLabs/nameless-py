from nameless_py.native.util.logging import logger
from nameless_py.native.util.encryption.data_encryption import (
    AESDataEncryption,
    DecryptionError,
)
from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer
from nameless_py.native.util.filesystem.symlink_manager import SymlinkUtil, SymlinkError
from typing import TypedDict
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


class SetServerAsDefaultParams(TypedDict):
    server_data_dir: str
    encrypted_name: str


class CheckServerExistsParams(TypedDict):
    server_data_dir: str
    encrypted_name: str


class DecryptServerParams(TypedDict):
    server_data_dir: str
    encrypted_name: str
    salt: bytes
    password: str


class CreateServerParams(TypedDict):
    server_data_dir: str
    server_name: str
    salt: bytes
    password: str
    max_messages: int


class SaveServerParams(TypedDict):
    server_data_dir: str
    encrypted_name: str
    server_data: bytes
    salt: bytes
    password: str


class ServerDataManager:
    def __init__(self):
        self.encryption = AESDataEncryption()

    @staticmethod
    def get_random_server_name() -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=16))

    def exists(self, params: CheckServerExistsParams) -> bool:
        return os.path.exists(
            os.path.join(params["server_data_dir"], params["encrypted_name"])
        )

    def create_default_if_not_exists(self, params: CreateServerParams) -> bytes:
        check_params: CheckServerExistsParams = {
            "server_data_dir": params["server_data_dir"],
            "encrypted_name": "default",
        }

        # Create If Not Exists
        if not self.exists(check_params):
            data = self.create(params)
            self.set_server_as_default(check_params)
            return data

        # Decrypt If Exists
        decryption_params: DecryptServerParams = {
            "server_data_dir": params["server_data_dir"],
            "encrypted_name": "default",
            "salt": params["salt"],
            "password": params["password"],
        }
        return self.decrypt(decryption_params)

    def set_server_as_default(self, params: SetServerAsDefaultParams) -> None:
        try:
            default_path = os.path.join(params["server_data_dir"], "default")
            target_path = os.path.join(
                params["server_data_dir"], params["encrypted_name"]
            )

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

    def decrypt(self, params: DecryptServerParams) -> bytes:
        try:
            server_data_path = os.path.join(
                params["server_data_dir"], params["encrypted_name"]
            )
            with open(server_data_path, "rb") as f:
                encrypted_data = f.read()
            return self.encryption.decrypt_data(
                {
                    "encrypted_data": encrypted_data,
                    "password": params["password"],
                    "salt": params["salt"],
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
            save_params: SaveServerParams = {
                "server_data_dir": params["server_data_dir"],
                "encrypted_name": encrypted_name,
                "server_data": server_data,
                "salt": params["salt"],
                "password": params["password"],
            }
            self.save(save_params)
            return server_data
        except Exception as e:
            logger.error(f"Failed to create new server data: {e}")
            raise ServerDataCreationError(f"Failed to create new server data: {e}")

    def save(self, params: SaveServerParams):
        try:
            if params["encrypted_name"] == "default":
                raise ServerDataSaveError("Cannot save server data with name 'default'")

            if not os.path.exists(params["server_data_dir"]):
                os.makedirs(params["server_data_dir"])
            encrypted_data = self.encryption.encrypt_data(
                {
                    "data": params["server_data"],
                    "password": params["password"],
                    "salt": params["salt"],
                }
            )
            server_data_path = os.path.join(
                params["server_data_dir"], params["encrypted_name"]
            )
            with open(server_data_path, "wb") as f:
                f.write(encrypted_data)
            default_path = os.path.join(params["server_data_dir"], "default")
            SymlinkUtil._create_symlink(server_data_path, default_path)
        except OSError as e:
            raise ServerDataSaveError(f"Failed to save server data: {e}")
        except Exception as e:
            logger.error(f"Failed to save server data: {e}")
            raise ServerDataSaveError(f"Failed to save server data: {e}")
