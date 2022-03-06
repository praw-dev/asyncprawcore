"""Provides the HTTP request handling interface."""
import asyncio
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

import aiohttp

from .const import TIMEOUT, __version__
from .exceptions import InvalidInvocation, RequestException

if TYPE_CHECKING:  # pragma: no cover
    from asyncio import AbstractEventLoop

    from .sessions import Session


class Requestor(object):
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
        session: Optional["Session"] = None,
        loop: Optional["AbstractEventLoop"] = None,
        timeout: float = TIMEOUT,
    ) -> None:
        """Create an instance of the Requestor class.

        :param user_agent: The user-agent for your application. Please follow Reddit's
            user-agent guidelines: https://github.com/reddit/reddit/wiki/API#rules
        :param oauth_url: The URL used to make OAuth requests to the Reddit site
            (default: ``"https://oauth.reddit.com"``).
        :param reddit_url: The URL used when obtaining access tokens (default:
            ``"https://www.reddit.com"``).
        :param session: A session to handle requests, compatible with
            ``aiohttp.ClientSession()`` (default: ``None``).
        :param timeout: How many seconds to wait for the server to send data before
            giving up (default: ``asyncprawcore.const.TIMEOUT``).

        """
        if user_agent is None or len(user_agent) < 7:
            raise InvalidInvocation("user_agent is not descriptive")

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

    async def close(self) -> None:
        """Call close on the underlying session."""
        return await self._http.close()

    async def request(
        self, *args, timeout: Optional[float] = None, **kwargs
    ) -> Union[Dict[str, Any], str, None]:
        """Issue the HTTP request capturing any errors that may occur."""
        try:
            return await self._http.request(
                *args, timeout=timeout or self.timeout, **kwargs
            )
        except Exception as exc:
            raise RequestException(exc, args, kwargs)
