"""Test for asyncprawcore.self.requestor.Requestor class."""
import asyncio

import pytest
from mock import Mock, patch

import asyncprawcore
from asyncprawcore import RequestException

from . import UnitTest


class TestRequestor(UnitTest):
    async def tearDown(self) -> None:
        if hasattr(self, "requestor"):
            if isinstance(self.requestor, asyncprawcore.requestor.Requestor):
                if not isinstance(self.requestor._http, Mock):
                    await self.requestor.close()

    def test_initialize(self):
        assert (
            self.requestor._http._default_headers["User-Agent"]
            == f"asyncprawcore:test (by /u/Lil_SpazJoekp) asyncprawcore/{asyncprawcore.__version__}"
        )

    def test_initialize__failures(self):
        for agent in [None, "shorty"]:
            with pytest.raises(asyncprawcore.InvalidInvocation):
                asyncprawcore.Requestor(agent)

    @patch("aiohttp.ClientSession")
    async def test_request__wrap_request_exceptions(self, mock_session):
        exception = Exception("asyncprawcore wrap_request_exceptions")
        session_instance = mock_session.return_value
        session_instance.request.side_effect = exception
        self.requestor = asyncprawcore.Requestor(
            "asyncprawcore:test (by /u/Lil_SpazJoekp)"
        )
        with pytest.raises(asyncprawcore.RequestException) as exception_info:
            await self.requestor.request("get", "http://a.b", data="bar")
        assert isinstance(exception_info.value, RequestException)
        assert exception is exception_info.value.original_exception
        assert exception_info.value.request_args == ("get", "http://a.b")
        assert exception_info.value.request_kwargs == {"data": "bar"}

    async def test_request__use_custom_session(self):
        override = "REQUEST OVERRIDDEN"
        custom_header = "CUSTOM SESSION HEADER"
        headers = {"session_header": custom_header}
        return_of_request = asyncio.Future()
        return_of_request.set_result(override)
        attrs = {
            "request.return_value": return_of_request,
            "_default_headers": headers,
        }
        session = Mock(**attrs)

        self.requestor = asyncprawcore.Requestor(
            "asyncprawcore:test (by /u/Lil_SpazJoekp)", session=session
        )
        assert (
            self.requestor._http._default_headers["User-Agent"]
            == f"asyncprawcore:test (by /u/Lil_SpazJoekp) asyncprawcore/{asyncprawcore.__version__}"
        )
        assert self.requestor._http._default_headers["session_header"] == custom_header

        assert await self.requestor.request("https://reddit.com") == override
