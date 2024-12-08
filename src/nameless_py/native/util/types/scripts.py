from typing import Callable, Optional, TypeAlias, TypeVar
from nameless_py.native.util.types.http import HttpResult

T = TypeVar("T")

ProcessType: TypeAlias = Callable[[bytes], T]
ChecksType: TypeAlias = Callable[[bytes, object, ProcessType[T]], HttpResult]


def process_unconditionally(
    func: Callable[..., bytes], request: Optional[bytes]
) -> bytes:
    try:
        if not request:
            return func()
        else:
            return func(request)
    except Exception as e:
        raise RuntimeError(f"Failed To Process Request: {e}")


def process_conditionally(
    process: ProcessType[T],
    checks: ChecksType[T],
    request: Optional[bytes],
    auxiliary: Optional[object],
) -> HttpResult:
    if not request or not auxiliary:
        raise ValueError("Request and auxiliary must be provided")
    try:
        processed_data = checks(request, auxiliary, process)
        return processed_data
    except ValueError as e:
        raise ValueError(f"Value error in process_conditionally: {e}")
    except Exception as e:
        raise RuntimeError(f"Error in process_conditionally: {e}")
