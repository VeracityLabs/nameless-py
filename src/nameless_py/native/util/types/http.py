from result import Result, Ok, Err, is_ok, is_err
from typing import Any, TypedDict


class HttpError(TypedDict):
    status: int
    detail: str


class HttpSuccess(TypedDict):
    status: int
    body: dict


HttpResult = Result[HttpSuccess, HttpError]


def http_ok(body: dict) -> HttpResult:
    return Ok({"status": 200, "body": body})


def http_err(status: int, detail: str) -> HttpResult:
    return Err({"status": status, "detail": detail})


def is_http_ok(result: HttpResult) -> bool:
    return is_ok(result) and result.ok_value["status"] == 200


def is_http_err(result: HttpResult) -> bool:
    return is_err(result) and result.err_value["status"] != 200


def get_http_value(result: HttpResult) -> Any:
    if is_http_ok(result):
        return result.unwrap()["body"]
    else:
        return result.unwrap_err()["detail"]
