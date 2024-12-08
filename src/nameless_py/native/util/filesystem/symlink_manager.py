import os


###
# Exceptions
###


# Base exception class for symlink-related errors
class SymlinkError(Exception):
    pass


# Raised when creating a new symlink fails
class SymlinkCreationError(Exception):
    pass


# Raised when resolving a symlink's target path fails
class SymlinkResolutionError(Exception):
    pass


# Raised when removing a symlink fails
class SymlinkDestructionError(Exception):
    pass


###
# Symlink Utility
###


class SymlinkUtil:
    @staticmethod
    def _create_symlink(target_path: str, symlink_path: str) -> None:
        """Create a symlink at symlink_path pointing to target_path.

        Args:
            target_path: Path that the symlink should point to
            symlink_path: Path where the symlink should be created

        Raises:
            SymlinkCreationError: If creating the symlink fails
            SymlinkError: For unexpected errors during creation
        """
        try:
            if os.path.exists(symlink_path):
                os.remove(symlink_path)
            os.symlink(target_path, symlink_path)
        except OSError as e:
            raise SymlinkCreationError(f"Failed to create symlink: {e}")
        except Exception as e:
            raise SymlinkError(f"Unexpected error creating symlink: {e}")

    @staticmethod
    def _resolve_symlink(symlink_path: str) -> str:
        """Resolve the target path that a symlink points to.

        Args:
            symlink_path: Path to the symlink to resolve

        Returns:
            str: The resolved target path, or empty string if symlink doesn't exist

        Raises:
            SymlinkResolutionError: If resolving the symlink fails
            SymlinkError: For unexpected errors during resolution
        """
        try:
            if not os.path.exists(symlink_path):
                return ""
            return os.path.realpath(symlink_path)
        except OSError as e:
            raise SymlinkResolutionError(f"Failed to resolve symlink: {e}")
        except Exception as e:
            raise SymlinkError(f"Unexpected error resolving symlink: {e}")

    @staticmethod
    def _destroy_symlink(symlink_path: str) -> None:
        """Remove a symlink if it exists.

        Args:
            symlink_path: Path to the symlink to remove

        Raises:
            SymlinkDestructionError: If removing the symlink fails
            SymlinkError: For unexpected errors during removal
        """
        try:
            if os.path.exists(symlink_path):
                os.remove(symlink_path)
        except OSError as e:
            raise SymlinkDestructionError(f"Failed to remove symlink: {e}")
        except Exception as e:
            raise SymlinkError(f"Unexpected error removing symlink: {e}")

    @staticmethod
    def exists(symlink_path: str) -> bool:
        """Check if a symlink exists at the given path.

        Args:
            symlink_path: Path to check for symlink existence

        Returns:
            bool: True if symlink exists, False otherwise

        Raises:
            SymlinkError: If checking for existence fails
        """
        try:
            return os.path.exists(symlink_path)
        except Exception as e:
            raise SymlinkError(f"Failed to check symlink existence: {e}")

    @staticmethod
    def read_link(symlink_path: str) -> str:
        """Read the target path that a symlink points to without resolving.

        Args:
            symlink_path: Path to the symlink to read

        Returns:
            str: The target path the symlink points to

        Raises:
            SymlinkResolutionError: If reading the symlink fails
            SymlinkError: For unexpected errors while reading
        """
        try:
            return os.readlink(symlink_path)
        except OSError as e:
            raise SymlinkResolutionError(f"Failed to read symlink: {e}")
        except Exception as e:
            raise SymlinkError(f"Unexpected error reading symlink: {e}")
