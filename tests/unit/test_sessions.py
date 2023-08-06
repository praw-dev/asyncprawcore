"""Test for asyncprawcore.Sessions module."""
import asyncio
import logging

import pytest
from aiohttp.web import HTTPRequestTimeout
from mock import patch
from testfixtures import LogCapture

import asyncprawcore
from asyncprawcore.exceptions import RequestException

from ..conftest import AsyncMock
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
    async def readonly_authorizer(self, refresh=True, requestor=None):
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor or self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        if refresh:
            await authorizer.refresh()
        return authorizer

    async def test_close(self):
        await asyncprawcore.Session(
            await self.readonly_authorizer(refresh=False)
        ).close()

    async def test_context_manager(self):
        async with asyncprawcore.Session(
            await self.readonly_authorizer(refresh=False)
        ) as session:
            assert isinstance(session, asyncprawcore.Session)

    def test_init__with_device_id_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator)
        asyncprawcore.Session(authorizer)

    def test_init__with_implicit_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        authorizer = asyncprawcore.ImplicitAuthorizer(authenticator, None, 0, "")
        asyncprawcore.Session(authorizer)

    def test_init__without_authenticator(self):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.Session(None)

    @patch("asyncio.sleep", return_value=None)
    @patch("aiohttp.ClientSession")
    async def test_request__connection_error_retry(self, mock_session, _):
        session_instance = mock_session.return_value
        self.requestor = asyncprawcore.requestor.Requestor(
            "asyncprawcore:test (by /u/Lil_SpazJoekp)", session=session_instance
        )
        try:
            session_instance.request.return_value = asyncio.Future()
            session_instance.request.return_value.set_result(
                AsyncMock(
                    status=200,
                    response_dict={
                        "access_token": "",
                        "expires_in": 99,
                        "scope": "",
                    },
                    headers={},
                )
            )

            authorizer = await self.readonly_authorizer()
            session_instance.request.reset_mock()

            # Fail on subsequent request
            exception = ConnectionError()
            session_instance.request.side_effect = exception

            expected = (
                "asyncprawcore",
                "WARNING",
                "Retrying due to ConnectionError() status: GET "
                "https://oauth.reddit.com/",
            )
        finally:
            session_instance.close()

        with LogCapture(level=logging.WARNING) as log_capture:
            with pytest.raises(RequestException) as exception_info:
                await asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert session_instance.request.call_count == 3

    @patch("asyncio.sleep", return_value=None)
    @patch("aiohttp.ClientSession")
    async def test_request__read_timeout_retry(self, mock_session, _):
        session_instance = mock_session.return_value
        self.requestor = asyncprawcore.requestor.Requestor(
            "asyncprawcore:test (by /u/Lil_SpazJoekp)", session=session_instance
        )
        session_instance.request.return_value = asyncio.Future()
        session_instance.request.return_value.set_result(
            AsyncMock(
                status=200,
                response_dict={
                    "access_token": "",
                    "expires_in": 99,
                    "scope": "",
                },
                headers={},
            )
        )
        authorizer = await self.readonly_authorizer()
        session_instance.request.reset_mock()

        # Fail on subsequent request
        exception = HTTPRequestTimeout()
        session_instance.request.side_effect = exception

        expected = (
            "asyncprawcore",
            "WARNING",
            "Retrying due to <HTTPRequestTimeout Request Timeout not prepared> "
            "status: "
            "GET https://oauth.reddit.com/",
        )

        with LogCapture(level=logging.WARNING) as log_capture:
            with pytest.raises(RequestException) as exception_info:
                await asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert session_instance.request.call_count == 3

    async def test_request__with_invalid_authorizer(self):
        session = asyncprawcore.Session(InvalidAuthorizer(self.requestor))
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await session.request("get", "/")


class TestSessionFunction(UnitTest):
    def test_session(self):
        assert isinstance(
            asyncprawcore.session(InvalidAuthorizer(self.requestor)),
            asyncprawcore.Session,
        )
