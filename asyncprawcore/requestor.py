"""Provides the HTTP request handling interface."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from warnings import warn

import aiohttp
from aiohttp import ClientTimeout

from .const import TIMEOUT
from .exceptions import InvalidInvocation, RequestException, ResponseException

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from collections.abc import AsyncGenerator

    from aiohttp import ClientResponse, ClientSession


class Requestor:
    """Requestor provides an interface to HTTP requests."""

    MIN_USER_AGENT_LENGTH = 7

    def __getattr__(self, attribute: str) -> object:  # pragma: no cover
        """Pass all undefined attributes to the ``_http`` attribute."""
        if attribute.startswith("__"):
            raise AttributeError(attribute)
        return getattr(self._http, attribute)

    def __init__(
        self,
        user_agent: str,
        oauth_url: str = "https://oauth.reddit.com",
        reddit_url: str = "https://www.reddit.com",
        session: ClientSession | None = None,
        loop: AbstractEventLoop | None = None,
        timeout: float = TIMEOUT,
    ) -> None:
        """Create an instance of the Requestor class.

        :param user_agent: The user-agent for your application. Please follow Reddit's
            user-agent guidelines: https://github.com/reddit/reddit/wiki/API#rules
        :param oauth_url: The URL used to make OAuth requests to the Reddit site
            (default: ``"https://oauth.reddit.com"``).
        :param reddit_url: The URL used when obtaining access tokens (default:
            ``"https://www.reddit.com"``).
        :param session: A session instance to handle requests, compatible with
            ``aiohttp.ClientSession()`` (default: ``None``).
        :param loop: The event loop to run the requestor on (default: ``None``).

            .. Deprecated:: 2.5.0

                The ``loop`` argument is deprecated and will be ignored.

        :param timeout: How many seconds to wait for the server to send data before
            giving up (default: ``asyncprawcore.const.TIMEOUT``).

        """
        # Imported locally to avoid an import cycle, with __init__
        from . import __version__  # noqa: PLC0415

        if loop is not None:
            msg = "The loop argument is deprecated and will be ignored."
            warn(msg, DeprecationWarning, stacklevel=2)

        if user_agent is None or len(user_agent) < self.MIN_USER_AGENT_LENGTH:
            msg = "user_agent is not descriptive"
            raise InvalidInvocation(msg)

        self.headers = {"User-Agent": f"{user_agent} asyncprawcore/{__version__}"}
        self.oauth_url = oauth_url
        self.reddit_url = reddit_url
        self.timeout = timeout

        self._http = session
        if self._http is not None and "User-Agent" not in self._http.headers:
            # ensure user-agent is set
            self._http.headers.update(self.headers)

    async def _ensure_session(self):
        """Ensure that the session is open."""
        if self._http is None or self._http.closed:
            self._http = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=None),
            )

    async def close(self) -> None:
        """Call close on the underlying session."""
        if self._http is not None and not self._http.closed:
            await self._http.close()

    @asynccontextmanager
    async def request(self, *args: Any, timeout: float | None = None, **kwargs: Any) -> AsyncGenerator[ClientResponse]:
        """Issue the HTTP request capturing any errors that may occur.

        :param args: Positional arguments to pass to ``aiohttp.ClientSession.request``.
        :param timeout: How many seconds to wait for the server to send data before
            giving up (default: ``None``).
        :param kwargs: Keyword arguments to pass to ``aiohttp.ClientSession.request``.

        :returns: The response from the request.

        :raises: RequestException: If an error occurs while issuing the request.

        """
        try:
            await self._ensure_session()
            kwargs_copy = kwargs.copy()
            if self._http is not None:
                async with self._http.request(
                    *args,
                    headers={**self.headers, **kwargs_copy.pop("headers", {})},
                    timeout=ClientTimeout(timeout or self.timeout),
                    **kwargs_copy,
                ) as request:
                    yield request
        except ResponseException as exc:
            raise exc
        except Exception as exc:  # noqa: BLE001
            raise RequestException(exc, args, kwargs) from exc
