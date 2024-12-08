import os
from nameless_py.native.util.logging import logger

SALT_SIZE = 16

###
# Exceptions
###


# Base exception class for salt-related errors
class SaltError(Exception):
    pass


# Raised when creating a new salt file fails
class SaltCreationError(SaltError):
    pass


# Raised when reading an existing salt file fails
class SaltReadError(SaltError):
    pass


# Raised when the salt file exists but has invalid data
class InvalidSaltError(SaltError):
    pass


###
# Salt Manager
###


class SaltManager:
    def __init__(self, salt_file_path: str):
        self.salt_file_path = salt_file_path

    def generate(self) -> bytes:
        try:
            if not os.path.exists(os.path.dirname(self.salt_file_path)):
                try:
                    os.makedirs(os.path.dirname(self.salt_file_path))
                except OSError as e:
                    raise SaltCreationError(
                        f"Failed to create directory for salt file: {e}"
                    )
            salt = os.urandom(SALT_SIZE)
            try:
                with open(self.salt_file_path, "wb") as f:
                    f.write(salt)
            except IOError as e:
                raise SaltCreationError(f"Failed to write salt to file: {e}")
            return salt
        except SaltCreationError:
            raise
        except Exception as e:
            logger.error(f"Failed to create new salt: {e}")
            raise SaltError(f"Failed to create new salt: {e}")

    def fetch(self) -> bytes:
        try:
            with open(self.salt_file_path, "rb") as f:
                salt = f.read()
            if len(salt) != SALT_SIZE:
                raise InvalidSaltError("Existing salt file has incorrect size")
            return salt
        except FileNotFoundError as e:
            raise SaltReadError(f"Salt file not found: {e}")
        except IOError as e:
            raise SaltReadError(f"Failed to read salt from file: {e}")
        except InvalidSaltError:
            raise
        except Exception as e:
            logger.error(f"Failed to read existing salt: {e}")
            raise SaltError(f"Failed to read existing salt: {e}")

    def salt_exists(self) -> bool:
        return os.path.exists(self.salt_file_path)

    def fetch_or_create(self) -> bytes:
        try:
            if not self.salt_exists():
                return self.generate()
            return self.fetch()
        except (SaltCreationError, SaltReadError, InvalidSaltError):
            raise
        except Exception as e:
            logger.error(f"Failed to get or create salt: {e}")
            raise SaltError(f"Failed to get or create salt: {e}")
