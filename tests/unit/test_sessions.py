"""Test for asyncprawcore.Sessions module."""
import logging
from unittest.mock import AsyncMock, patch

import aiohttp.client
import pytest
from aiohttp.web import HTTPRequestTimeout

import asyncprawcore
from asyncprawcore.exceptions import RequestException

from . import UnitTest


class InvalidAuthorizer(asyncprawcore.Authorizer):
    def __init__(self, requestor):
        super(InvalidAuthorizer, self).__init__(
            asyncprawcore.TrustedAuthenticator(
                requestor,
                pytest.placeholders.client_id,
                pytest.placeholders.client_secret,
            )
        )

    def is_valid(self):
        return False


class TestSession(UnitTest):
    @pytest.fixture
    def readonly_authorizer(self, trusted_authenticator):
        return asyncprawcore.ReadOnlyAuthorizer(trusted_authenticator)

    async def test_close(self, readonly_authorizer):
        await asyncprawcore.Session(readonly_authorizer).close()

    async def test_context_manager(self, readonly_authorizer):
        async with asyncprawcore.Session(readonly_authorizer) as session:
            assert isinstance(session, asyncprawcore.Session)

    def test_init__with_device_id_authorizer(self, untrusted_authenticator):
        authorizer = asyncprawcore.DeviceIDAuthorizer(untrusted_authenticator)
        asyncprawcore.Session(authorizer)

    def test_init__with_implicit_authorizer(self, untrusted_authenticator):
        authorizer = asyncprawcore.ImplicitAuthorizer(
            untrusted_authenticator, None, 0, ""
        )
        asyncprawcore.Session(authorizer)

    def test_init__without_authenticator(self):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.Session(None)

    @patch("aiohttp.ClientSession")
    @pytest.mark.parametrize(
        "exception",
        [ConnectionError(), HTTPRequestTimeout()],
        ids=["ConnectionError", "HTTPRequestTimeout"],
    )
    async def test_request__retry(self, mock_session, exception, caplog):
        caplog.set_level(logging.WARNING)
        session_instance = mock_session.return_value
        # Handle Auth
        response_mock = AsyncMock(spec=aiohttp.client.ClientResponse)
        response_mock.status = 200
        response_mock.headers = {}
        session_instance.request = AsyncMock(return_value=response_mock)
        # session_instance.request.return_value = asyncio.Future()
        session_instance.request.return_value = AsyncMock(
            status=200,
            headers={},
        )
        session_instance.request.return_value.json = AsyncMock(
            return_value={
                "access_token": "",
                "expires_in": 99,
                "scope": "",
            },
        )
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by u/Lil_SpazJoekp)")
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        await authorizer.refresh()
        session_instance.request.reset_mock()
        # Fail on subsequent request
        session_instance.request.side_effect = exception

        with pytest.raises(RequestException) as exception_info:
            await asyncprawcore.Session(authorizer).request("GET", "/")
        message = (
            "<HTTPRequestTimeout Request Timeout not prepared>"
            if isinstance(exception, HTTPRequestTimeout)
            else f"{exception.__class__.__name__}()"
        )
        assert (
            "asyncprawcore",
            logging.WARNING,
            f"Retrying due to {message} status: GET https://oauth.reddit.com/",
        ) in caplog.record_tuples
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert session_instance.request.call_count == 3

    async def test_request__with_invalid_authorizer(self, requestor):
        session = asyncprawcore.Session(InvalidAuthorizer(requestor))
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await session.request("get", "/")


class TestSessionFunction(UnitTest):
    def test_session(self, requestor):
        assert isinstance(
            asyncprawcore.session(InvalidAuthorizer(requestor)), asyncprawcore.Session
        )
