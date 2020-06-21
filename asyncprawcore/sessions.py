"""asyncprawcore.sessions: Provides asyncprawcore.Session and asyncprawcore.session."""
from copy import deepcopy
import logging
import random
import asyncio
from json.decoder import JSONDecodeError
from aiohttp.web import HTTPRequestTimeout
from urllib.parse import urljoin
from .codes import codes

from .auth import BaseAuthorizer
from .const import TIMEOUT
from .rate_limit import RateLimiter
from .exceptions import (
    BadJSON,
    BadRequest,
    Conflict,
    InvalidInvocation,
    NotFound,
    Redirect,
    RequestException,
    ServerError,
    SpecialError,
    TooLarge,
    UnavailableForLegalReasons,
)
from .util import authorization_error_class

log = logging.getLogger(__package__)


class RetryStrategy(object):
    """An abstract class for scheduling request retries.

    The strategy controls both the number and frequency of retry attempts.

    Instances of this class are immutable.

    """

    def sleep(self):
        """Sleep until we are ready to attempt the request."""
        sleep_seconds = self._sleep_seconds()
        if sleep_seconds is not None:
            message = "Sleeping: {:0.2f} seconds prior to retry".format(
                sleep_seconds
            )
            log.debug(message)
            asyncio.sleep(sleep_seconds)


class FiniteRetryStrategy(RetryStrategy):
    """A ``RetryStrategy`` that retries requests a finite number of times."""

    def _sleep_seconds(self):
        if self._retries < 3:
            base = 0 if self._retries == 2 else 2
            return base + 2 * random.random()
        return None

    def __init__(self, retries=3):
        """Initialize the strategy.

        :param retries: Number of times to attempt a request.

        """
        self._retries = retries

    def consume_available_retry(self):
        """Allow one fewer retry."""
        return type(self)(self._retries - 1)

    def should_retry_on_failure(self):
        """Return ``True`` if and only if the strategy will allow another retry."""
        return self._retries > 1


class Session(object):
    """The low-level connection interface to reddit's API."""

    RETRY_EXCEPTIONS = (ConnectionError, HTTPRequestTimeout)
    RETRY_STATUSES = {
        520,
        522,
        codes["bad_gateway"],
        codes["gateway_timeout"],
        codes["internal_server_error"],
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
        codes["not_found"]: NotFound,
        codes["request_entity_too_large"]: TooLarge,
        codes["service_unavailable"]: ServerError,
        codes["unauthorized"]: authorization_error_class,
        codes[
            "unavailable_for_legal_reasons"
        ]: UnavailableForLegalReasons,  # CloudFlare status (not named in requests)
        520: ServerError,
        522: ServerError,
    }
    SUCCESS_STATUSES = {codes["created"], codes["ok"]}

    @staticmethod
    def _log_request(data, method, params, url):
        log.debug("Fetching: {} {}".format(method, url))
        log.debug("Data: {}".format(data))
        log.debug("Params: {}".format(params))

    @staticmethod
    def _retry_sleep(retries):
        if retries < 3:
            base = 0 if retries == 2 else 2
            sleep_seconds = base + 2 * random.random()
            message = "Sleeping: {:0.2f} seconds prior to retry".format(
                sleep_seconds
            )
            log.debug(message)
            asyncio.sleep(sleep_seconds)

    def __init__(self, authorizer):
        """Preprare the connection to reddit's API.

        :param authorizer: An instance of :class:`Authorizer`.

        """
        if not isinstance(authorizer, BaseAuthorizer):
            raise InvalidInvocation(
                "invalid Authorizer: {}".format(authorizer)
            )
        self._authorizer = authorizer
        self._rate_limiter = RateLimiter()
        self._retry_strategy_class = FiniteRetryStrategy

    async def __aenter__(self):
        """Allow this object to be used as a context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Allow this object to be used as a context manager."""
        await self.close()

    async def _do_retry(
        self,
        data,
        json,
        method,
        params,
        response,
        retry_strategy_state,
        saved_exception,
        timeout,
        url,
    ):
        if saved_exception:
            status = repr(saved_exception)
        else:
            status = response.status
        log.warning(
            "Retrying due to {} status: {} {}".format(status, method, url)
        )
        return await self._request_with_retries(
            data=data,
            json=json,
            method=method,
            params=params,
            timeout=timeout,
            url=url,
            retry_strategy_state=retry_strategy_state.consume_available_retry(),  # noqa: E501
        )

    async def _make_request(
        self, data, json, method, params, retry_strategy_state, timeout, url,
    ):
        try:
            response = await self._rate_limiter.call(
                self._requestor.request,
                self._set_header_callback,
                method,
                url,
                allow_redirects=False,
                data=data,
                json=json,
                params=params,
                timeout=timeout,
            )
            log.debug(
                "Response: {} ({} bytes)".format(
                    response.status, response.headers.get("content-length")
                )
            )
            return response, None
        except RequestException as exception:
            if not retry_strategy_state.should_retry_on_failure() or not isinstance(  # noqa: E501
                exception.original_exception, self.RETRY_EXCEPTIONS
            ):
                raise
            return None, exception.original_exception

    async def _request_with_retries(
        self,
        data,
        json,
        method,
        params,
        timeout,
        url,
        retry_strategy_state=None,
    ):
        if retry_strategy_state is None:
            retry_strategy_state = self._retry_strategy_class()
        self._log_request(data, method, params, url)
        response, saved_exception = await self._make_request(
            data, json, method, params, retry_strategy_state, timeout, url,
        )

        do_retry = False
        if response is not None and response.status == codes["unauthorized"]:
            self._authorizer._clear_access_token()
            if hasattr(self._authorizer, "refresh"):
                do_retry = True

        if retry_strategy_state.should_retry_on_failure() and (
            do_retry
            or response is None
            or response.status in self.RETRY_STATUSES
        ):
            return await self._do_retry(
                data,
                json,
                method,
                params,
                response,
                retry_strategy_state,
                saved_exception,
                timeout,
                url,
            )
        elif response.status in self.STATUS_EXCEPTIONS:
            raise self.STATUS_EXCEPTIONS[response.status](response)
        elif response.status == codes["no_content"]:
            return
        assert (
            response.status in self.SUCCESS_STATUSES
        ), "Unexpected status code: {}".format(response.status)
        if response.headers.get("content-length") == "0":
            return ""
        try:
            return await response.json()
        except (JSONDecodeError, ValueError):
            raise BadJSON(response)

    async def _set_header_callback(self):
        if not self._authorizer.is_valid() and hasattr(
            self._authorizer, "refresh"
        ):
            await self._authorizer.refresh()
        return {
            "Authorization": "bearer {}".format(self._authorizer.access_token)
        }

    @property
    def _requestor(self):
        return self._authorizer._authenticator._requestor

    async def close(self):
        """Close the session and perform any clean up."""
        await self._requestor.close()

    async def request(
        self,
        method,
        path,
        data=None,
        files=None,
        json=None,
        params=None,
        timeout=TIMEOUT,
    ):
        """Return the json content from the resource at ``path``.

        :param method: The request verb. E.g., get, post, put.
        :param path: The path of the request. This path will be combined with
            the ``oauth_url`` of the Requestor.
        :param data: Dictionary, bytes, or file-like object to send in the body
            of the request.
        :param files: Dictionary, mapping ``filename`` to file-like object.
        :param json: Object to be serialized to JSON in the body of the
            request.
        :param params: The query parameters to send with the request.

        Automatically refreshes the access token if it becomes invalid and a
        refresh token is available. Raises InvalidInvocation in such a case if
        a refresh token is not available.

        """
        params = deepcopy(params) or {}
        params["raw_json"] = 1
        if isinstance(json, dict):
            json = deepcopy(json)
            json["api_type"] = "json"
        data = self.validate_data_files(data, files)
        url = urljoin(self._requestor.oauth_url, path)
        return await self._request_with_retries(
            data=data,
            json=json,
            method=method,
            params=params,
            timeout=timeout,
            url=url,
        )

    @staticmethod
    def validate_data_files(data, files):
        """Transfers the files and data from the arguments into the data.

        This is done to maintain consistency with prawcore
        :param data dictionary of data
        :param files dictionary of "file" mapped to file-stream
        """
        if data is not None and files is not None:
            raise InvalidInvocation(
                "Both data and files cannot be non-None simultaneously"
            )
        if isinstance(data, dict):
            data = deepcopy(data)
            data["api_type"] = "json"
            if files is not None:
                data.update(files)
            data = sorted(data.items())
        if isinstance(files, dict):
            data = files
        return data


def session(authorizer=None):
    """Return a :class:`Session` instance.

    :param authorizer: An instance of :class:`Authorizer`.

    """
    return Session(authorizer=authorizer)
