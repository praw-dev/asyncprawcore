"""asyncprawcore.sessions: Provides asyncprawcore.Session and asyncprawcore.session."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass
from pprint import pformat
from typing import TYPE_CHECKING, BinaryIO, TextIO
from urllib.parse import urljoin

from aiohttp.web import HTTPRequestTimeout

from .auth import BaseAuthorizer
from .codes import codes
from .const import TIMEOUT, WINDOW_SIZE
from .exceptions import (
    BadJSON,
    BadRequest,
    Conflict,
    InvalidInvocation,
    NotFound,
    Redirect,
    RequestException,
    ResponseException,
    ServerError,
    SpecialError,
    TooLarge,
    TooManyRequests,
    UnavailableForLegalReasons,
    URITooLong,
)
from .rate_limit import RateLimiter
from .util import authorization_error_class

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from aiohttp import ClientResponse
    from typing_extensions import Self

    from .auth import Authorizer
    from .requestor import Requestor

log = logging.getLogger(__package__)


class RetryStrategy(ABC):
    """An abstract class for scheduling request retries.

    The strategy controls both the number and frequency of retry attempts.

    Instances of this class are immutable.

    """

    @abstractmethod
    def _sleep_seconds(self) -> float | None:
        pass

    @abstractmethod
    def consume_available_retry(self) -> RetryStrategy:
        """Allow one fewer retry."""

    @abstractmethod
    def should_retry_on_failure(self) -> bool:
        """Return True when a retry should occur."""

    async def sleep(self) -> None:
        """Sleep until we are ready to attempt the request."""
        sleep_seconds = self._sleep_seconds()
        if sleep_seconds is not None:
            message = f"Sleeping: {sleep_seconds:0.2f} seconds prior to retry"
            log.debug(message)
            await asyncio.sleep(sleep_seconds)


@dataclass(frozen=True)
class FiniteRetryStrategy(RetryStrategy):
    """A ``RetryStrategy`` that retries requests a finite number of times."""

    DEFAULT_RETRIES = 2

    retries: int = DEFAULT_RETRIES

    def _sleep_seconds(self) -> float | None:
        if self.retries < self.DEFAULT_RETRIES:
            base = 0 if self.retries > 0 else 2
            return base + 2 * random.random()  # noqa: S311
        return None

    def consume_available_retry(self) -> FiniteRetryStrategy:
        """Allow one fewer retry."""
        return type(self)(retries=self.retries - 1)

    def should_retry_on_failure(self) -> bool:
        """Return ``True`` if and only if the strategy will allow another retry."""
        return self.retries > 0


class Session:
    """The low-level connection interface to Reddit's API."""

    RETRY_EXCEPTIONS = (ConnectionError, HTTPRequestTimeout)
    RETRY_STATUSES = {
        520,
        522,
        codes["bad_gateway"],
        codes["gateway_timeout"],
        codes["internal_server_error"],
        codes["request_timeout"],
        codes["service_unavailable"],
    }
    STATUS_EXCEPTIONS = {
        codes["bad_gateway"]: ServerError,
        codes["bad_request"]: BadRequest,
        codes["conflict"]: Conflict,
        codes["found"]: Redirect,
        codes["forbidden"]: authorization_error_class,
        codes["gateway_timeout"]: ServerError,
        codes["internal_server_error"]: ServerError,
        codes["media_type"]: SpecialError,
        codes["moved_permanently"]: Redirect,
        codes["not_found"]: NotFound,
        codes["request_entity_too_large"]: TooLarge,
        codes["request_uri_too_large"]: URITooLong,
        codes["service_unavailable"]: ServerError,
        codes["too_many_requests"]: TooManyRequests,
        codes["unauthorized"]: authorization_error_class,
        codes[
            "unavailable_for_legal_reasons"
        ]: UnavailableForLegalReasons,  # Cloudflare's status (not named in requests)
        520: ServerError,
        522: ServerError,
    }
    SUCCESS_STATUSES = {codes["accepted"], codes["created"], codes["ok"]}

    @staticmethod
    def _log_request(
        *,
        data: list[tuple[str, object]] | None,
        method: str,
        params: dict[str, object],
        url: str,
    ) -> None:
        log.debug("Fetching: %s %s at %s", method, url, time.monotonic())
        log.debug("Data: %s", pformat(data))
        log.debug("Params: %s", pformat(params))

    @staticmethod
    def _preprocess_dict(data: dict[str, object] | None) -> dict[str, object]:
        new_data = {}
        if data:
            for key, value in data.items():
                if isinstance(value, bool):
                    new_data[key] = str(value).lower()
                elif value is not None:
                    new_data[key] = str(value) if not isinstance(value, str) else value
        return new_data

    @property
    def _requestor(self) -> Requestor:
        return self._authorizer._authenticator._requestor

    async def __aenter__(self) -> Self:
        """Allow this object to be used as a context manager."""
        return self

    async def __aexit__(self, *_args) -> None:
        """Allow this object to be used as a context manager."""
        await self.close()

    def __init__(
        self,
        authorizer: BaseAuthorizer | None,
        window_size: int = WINDOW_SIZE,
    ) -> None:
        """Prepare the connection to Reddit's API.

        :param authorizer: An instance of :class:`.Authorizer`.
        :param window_size: The size of the rate limit reset window in seconds.

        """
        if not isinstance(authorizer, BaseAuthorizer):
            msg = f"invalid Authorizer: {authorizer}"
            raise InvalidInvocation(msg)
        self._authorizer = authorizer
        self._rate_limiter = RateLimiter(window_size=window_size)
        self._retry_strategy_class = FiniteRetryStrategy

    async def _do_retry(
        self,
        *,
        data: list[tuple[str, object]] | None,
        files: dict[str, BinaryIO | TextIO] | None,
        json: dict[str, object] | None,
        method: str,
        params: dict[str, object],
        retry_strategy_state: FiniteRetryStrategy,
        status: str,
        timeout: float,
        url: str,
    ) -> dict[str, object] | str | None:
        log.warning("Retrying due to %s: %s %s", status, method, url)
        return await self._request_with_retries(
            data=data,
            files=files,
            json=json,
            method=method,
            params=params,
            retry_strategy_state=retry_strategy_state.consume_available_retry(),
            timeout=timeout,
            url=url,
            # noqa: E501
        )

    @asynccontextmanager
    async def _make_request(
        self,
        data: list[tuple[str, object]] | None,
        files: dict[str, BinaryIO | TextIO] | None,
        json: dict[str, object] | None,
        method: str,
        params: dict[str, object],
        timeout: float,
        url: str,
    ) -> AsyncGenerator[ClientResponse]:
        async with self._rate_limiter.call(
            self._requestor.request,
            self._set_header_callback,
            method,
            url,
            allow_redirects=False,
            data=data,
            files=files,
            json=json,
            params=params,
            timeout=timeout,
        ) as response:
            log.debug(
                "Response: %s (%s bytes) (rst-%s:rem-%s:used-%s ratelimit) at %s",
                response.status,
                response.headers.get("content-length"),
                response.headers.get("x-ratelimit-reset"),
                response.headers.get("x-ratelimit-remaining"),
                response.headers.get("x-ratelimit-used"),
                time.monotonic(),
            )
            yield response

    def _preprocess_params(self, params: dict[str, object] | None) -> dict[str, object]:
        """Preprocess params before request.

        This is to convert requests that are formatted for the ``requests`` package to
        be compatible with ``aiohttp`` package. The motivation for this is so that
        ``praw`` and ``asyncpraw`` can remain as similar as possible and thus making
        contributions to ``asyncpraw`` simpler.

        This method does the following:

        - Removes keys that have a value of ``None`` from ``params``.
        - Casts bool values in ``params`` to str.

        :param params: The query parameters to send with the request.

        """
        return self._preprocess_dict(params)

    async def _request_with_retries(  # noqa: PLR0912
        self,
        *,
        data: list[tuple[str, object]] | None,
        files: dict[str, BinaryIO | TextIO] | None,
        json: dict[str, object] | None,
        method: str,
        params: dict[str, object],
        retry_strategy_state: FiniteRetryStrategy | None = None,
        timeout: float,
        url: str,
    ) -> dict[str, object] | str | None:
        if retry_strategy_state is None:
            retry_strategy_state = self._retry_strategy_class()

        await retry_strategy_state.sleep()
        self._log_request(data=data, method=method, params=params, url=url)

        try:
            async with self._make_request(
                data=data,
                files=files,
                json=json,
                method=method,
                params=params,
                timeout=timeout,
                url=url,
            ) as response:
                retry_status = None
                if response.status == codes["unauthorized"]:
                    self._authorizer._clear_access_token()
                    if hasattr(self._authorizer, "refresh"):
                        retry_status = f"{response.status} status"
                elif response.status in self.RETRY_STATUSES:
                    retry_status = f"{response.status} status"

                if retry_status is not None and retry_strategy_state.should_retry_on_failure():
                    return await self._do_retry(
                        data=data,
                        files=files,
                        json=json,
                        method=method,
                        params=params,
                        retry_strategy_state=retry_strategy_state,
                        status=retry_status,
                        timeout=timeout,
                        url=url,
                    )
                if response.status == codes["no_content"]:
                    return None
                if response.status in self.STATUS_EXCEPTIONS:
                    if response.status == codes["media_type"]:
                        # since exception class needs response.json
                        raise self.STATUS_EXCEPTIONS[response.status](response, await response.json())
                    raise self.STATUS_EXCEPTIONS[response.status](response)
                if response.status not in self.SUCCESS_STATUSES:
                    raise ResponseException(response)
                if response.headers.get("content-length") == "0":
                    return ""
                try:
                    return await response.json()
                except ValueError:
                    raise BadJSON(response) from None
        except RequestException as exception:
            if retry_strategy_state.should_retry_on_failure() and isinstance(  # noqa: E501
                exception.original_exception, self.RETRY_EXCEPTIONS
            ):
                return await self._do_retry(
                    data=data,
                    files=files,
                    json=json,
                    method=method,
                    params=params,
                    retry_strategy_state=retry_strategy_state,
                    status=repr(exception.original_exception),
                    timeout=timeout,
                    url=url,
                )
            raise

    async def _set_header_callback(self) -> dict[str, str]:
        refresh_method = getattr(self._authorizer, "refresh", None)
        if not self._authorizer.is_valid() and refresh_method is not None:
            await refresh_method()
        return {"Authorization": f"bearer {self._authorizer.access_token}"}

    async def close(self) -> None:
        """Close the session and perform any clean up."""
        await self._requestor.close()

    async def request(
        self,
        method: str,
        path: str,
        data: dict[str, object] | None = None,
        files: dict[str, BinaryIO | TextIO] | None = None,
        json: dict[str, object] | None = None,
        params: dict[str, object] | None = None,
        timeout: float = TIMEOUT,
    ) -> dict[str, object] | str | None:
        """Return the json content from the resource at ``path``.

        :param method: The request verb. E.g., ``"GET"``, ``"POST"``, ``"PUT"``.
        :param path: The path of the request. This path will be combined with the
            ``oauth_url`` of the Requestor.
        :param data: Dictionary, bytes, or file-like object to send in the body of the
            request.
        :param files: Dictionary, mapping ``filename`` to file-like object.
        :param json: Object to be serialized to JSON in the body of the request.
        :param params: The query parameters to send with the request.
        :param timeout: Specifies a particular timeout, in seconds.

        Automatically refreshes the access token if it becomes invalid and a refresh
        token is available.

        :raises: :class:`.InvalidInvocation` in such a case if a refresh token is not
            available.

        """
        params = self._preprocess_params(deepcopy(params) or {})
        params["raw_json"] = "1"
        if isinstance(data, dict):
            data = self._preprocess_dict(deepcopy(data))
            data["api_type"] = "json"
            data_list = sorted(data.items())
        else:
            data_list = data
        if isinstance(json, dict):
            json = deepcopy(json)
            json["api_type"] = "json"
        url = urljoin(self._requestor.oauth_url, path)
        return await self._request_with_retries(
            data=data_list,
            files=files,
            json=json,
            method=method,
            params=params,
            timeout=timeout,
            url=url,
        )


def session(
    authorizer: Authorizer | None = None,
    window_size: int = WINDOW_SIZE,
) -> Session:
    """Return a :class:`.Session` instance.

    :param authorizer: An instance of :class:`.Authorizer`.
    :param window_size: The size of the rate limit reset window in seconds.

    """
    return Session(authorizer=authorizer, window_size=window_size)
