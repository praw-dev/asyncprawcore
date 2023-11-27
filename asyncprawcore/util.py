"""Provide utility for the asyncprawcore package."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import Forbidden, InsufficientScope, InvalidToken

if TYPE_CHECKING:
    from aiohttp import ClientResponse

_auth_error_mapping = {
    403: Forbidden,
    "insufficient_scope": InsufficientScope,
    "invalid_token": InvalidToken,
}


def authorization_error_class(
    response: ClientResponse,
) -> InvalidToken | (Forbidden | InsufficientScope):
    """Return an exception instance that maps to the OAuth Error.

    :param response: The HTTP response containing a www-authenticate error.

    """
    message = response.headers.get("www-authenticate")
    error: int | str
    error = message.replace('"', "").rsplit("=", 1)[1] if message else response.status
    return _auth_error_mapping[error](response)
