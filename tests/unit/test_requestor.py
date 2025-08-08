"""Test for asyncprawcore.self.requestor.Requestor class."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import asyncprawcore
from asyncprawcore import RequestException

from . import UnitTest


class TestRequestor(UnitTest):
    async def test_deprecated_loop(self):
        with pytest.warns(DeprecationWarning, match="The loop argument is deprecated and will be ignored."):
            asyncprawcore.Requestor("asyncprawcore:test (by u/Lil_SpazJoekp)", loop=asyncio.get_event_loop())

    async def test_initialize(self, requestor):
        async with requestor.request("get", "https://reddit.com") as _:
            pass
        assert (
            requestor._http._default_headers["User-Agent"]
            == f"asyncprawcore:test (by u/Lil_SpazJoekp) asyncprawcore/{asyncprawcore.__version__}"
        )

    async def test_initialize__failures(self):
        for agent in [None, "shorty"]:
            with pytest.raises(asyncprawcore.InvalidInvocation):
                asyncprawcore.Requestor(agent)

    async def test_request__use_custom_session(self):
        override = "REQUEST OVERRIDDEN"
        custom_header = "CUSTOM SESSION HEADER"
        headers = {"session_header": custom_header}

        expected_response = MagicMock()
        expected_response.content.read = AsyncMock(return_value=override)
        return_of_request = MagicMock()
        return_of_request.__aenter__ = AsyncMock()
        return_of_request.__aenter__.return_value = expected_response

        session = MagicMock()
        session.request.return_value = return_of_request
        session.headers = headers
        session.closed = False
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by u/Lil_SpazJoekp)", session=session)

        assert (
            requestor._http.headers["User-Agent"]
            == f"asyncprawcore:test (by u/Lil_SpazJoekp) asyncprawcore/{asyncprawcore.__version__}"
        )
        assert requestor._http.headers["session_header"] == custom_header

        async with requestor.request("get", "https://reddit.com") as response:
            assert await response.content.read() == override

    @patch("aiohttp.ClientSession")
    async def test_request__wrap_request_exceptions(self, mock_session):
        exception = Exception("asyncprawcore wrap_request_exceptions")
        session_instance = mock_session.return_value
        session_instance.request.side_effect = exception
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by u/Lil_SpazJoekp)")
        with pytest.raises(asyncprawcore.RequestException) as exception_info:
            async with requestor.request("get", "http://a.b", data="bar") as _:
                pass  # pragma: no cover
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert exception_info.value.request_args == ("get", "http://a.b")
        assert exception_info.value.request_kwargs == {"data": "bar"}

    @patch("aiohttp.ClientSession")
    async def test_request__wrap_request_exceptions__timeout(self, mock_session):
        exception = asyncio.TimeoutError()
        session_instance = mock_session.return_value
        session_instance.request.side_effect = exception
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by u/Lil_SpazJoekp)")
        with pytest.raises(asyncprawcore.RequestException) as exception_info:
            async with requestor.request("get", "http://a.b", data="bar") as _:
                pass  # pragma: no cover
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert str(exception_info.value) == "error with request TimeoutError"
        assert exception_info.value.request_args == ("get", "http://a.b")
        assert exception_info.value.request_kwargs == {"data": "bar"}
