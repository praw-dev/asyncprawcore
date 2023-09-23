"""Provides the HTTP request handling interface."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import aiohttp
from aiohttp import ClientSession

from .const import TIMEOUT, __version__
from .exceptions import InvalidInvocation, RequestException

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop

    from aiohttp import ClientResponse


class Requestor:
    """Requestor provides an interface to HTTP requests."""

    def __getattr__(self, attribute: str) -> Any:  # pragma: no cover
        """Pass all undefined attributes to the ``_http`` attribute."""
        if attribute.startswith("__"):
            raise AttributeError
        return getattr(self._http, attribute)

    def __init__(
        self,
        user_agent: str,
        oauth_url: str = "https://oauth.reddit.com",
        reddit_url: str = "https://www.reddit.com",
        session: ClientSession | None = None,
        loop: AbstractEventLoop = None,
        timeout: float = TIMEOUT,
    ):
        """Create an instance of the Requestor class.

        :param user_agent: The user-agent for your application. Please follow Reddit's
            user-agent guidelines: https://github.com/reddit/reddit/wiki/API#rules
        :param oauth_url: The URL used to make OAuth requests to the Reddit site
            (default: ``"https://oauth.reddit.com"``).
        :param reddit_url: The URL used when obtaining access tokens (default:
            ``"https://www.reddit.com"``).
        :param session: A session instance to handle requests, compatible with
            ``aiohttp.ClientSession()`` (default: ``None``).
        :param timeout: How many seconds to wait for the server to send data before
            giving up (default: ``asyncprawcore.const.TIMEOUT``).

        """
        if user_agent is None or len(user_agent) < 7:
            msg = "user_agent is not descriptive"
            raise InvalidInvocation(msg)

        self.loop = loop or asyncio.get_event_loop()
        self._http = session or aiohttp.ClientSession(
            loop=self.loop, timeout=aiohttp.ClientTimeout(total=None)
        )
        self._http._default_headers[
            "User-Agent"
        ] = f"{user_agent} asyncprawcore/{__version__}"

        self.oauth_url = oauth_url
        self.reddit_url = reddit_url
        self.timeout = timeout

    async def close(self):
        """Call close on the underlying session."""
        await self._http.close()

    async def request(
        self, *args: Any, timeout: float | None = None, **kwargs: Any
    ) -> ClientResponse:
        """Issue the HTTP request capturing any errors that may occur."""
        try:
            return await self._http.request(
                *args, timeout=timeout or self.timeout, **kwargs
            )
        except Exception as exc:  # noqa: BLE001
            raise RequestException(exc, args, kwargs) from None
