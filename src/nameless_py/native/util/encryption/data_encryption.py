import os
from abc import ABC, abstractmethod
from typing import TypedDict
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

KEY_LENGTH = 32
IV_SIZE = 16

###
# Exceptions
###


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


###
# Encryption and Decryption
###


class EncryptionParams(TypedDict):
    data: bytes
    password: str
    salt: bytes


class DecryptionParams(TypedDict):
    encrypted_data: bytes
    password: str
    salt: bytes


class DataEncryption(ABC):
    @abstractmethod
    def encrypt_data(self, params: EncryptionParams) -> bytes:
        pass

    @abstractmethod
    def decrypt_data(self, params: DecryptionParams) -> bytes:
        pass


class AESDataEncryption(DataEncryption):
    def encrypt_data(self, params: EncryptionParams) -> bytes:
        try:
            key = PBKDF2(params["password"], params["salt"], dkLen=KEY_LENGTH)
            iv = os.urandom(IV_SIZE)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(pad(params["data"], AES.block_size))
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt data: {e}")

    def decrypt_data(self, params: DecryptionParams) -> bytes:
        try:
            key = PBKDF2(params["password"], params["salt"], dkLen=KEY_LENGTH)
            iv = params["encrypted_data"][:IV_SIZE]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(
                cipher.decrypt(params["encrypted_data"][IV_SIZE:]), AES.block_size
            )
        except ValueError as e:
            raise DecryptionError(f"Failed to decrypt data: {e}")
