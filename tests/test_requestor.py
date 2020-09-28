"""Test for asyncprawcore.requestor.Requestor class."""
import asyncprawcore
import asynctest
import asyncio
from mock import patch, Mock
from asyncprawcore import RequestException


class RequestorTest(asynctest.TestCase):
    async def tearDown(self) -> None:
        if hasattr(self, "requestor"):
            if isinstance(self.requestor, asyncprawcore.requestor.Requestor):
                if not isinstance(self.requestor._http, Mock):
                    await self.requestor.close()

    async def test_initialize(self):
        self.requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        self.assertEqual(
            f"asyncprawcore:test (by /u/bboe) asyncprawcore/{asyncprawcore.__version__}",
            self.requestor._http._default_headers["User-Agent"],
        )

    def test_initialize__failures(self):
        for agent in [None, "shorty"]:
            with self.assertRaises(asyncprawcore.InvalidInvocation):
                self.requestor = asyncprawcore.Requestor(agent)

    @patch("aiohttp.ClientSession")
    async def test_request__wrap_request_exceptions(self, mock_session):
        exception = Exception("asyncprawcore wrap_request_exceptions")
        session_instance = mock_session.return_value
        session_instance.request.side_effect = exception
        self.requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        with self.assertRaises(asyncprawcore.RequestException) as context_manager:
            await self.requestor.request("get", "http://a.b", data="bar")
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(("get", "http://a.b"), context_manager.exception.request_args)
        self.assertEqual({"data": "bar"}, context_manager.exception.request_kwargs)

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
            "asyncprawcore:test (by /u/bboe)", session=session
        )

        self.assertEqual(
            f"asyncprawcore:test (by /u/bboe) asyncprawcore/{asyncprawcore.__version__}",
            self.requestor._http._default_headers["User-Agent"],
        )
        self.assertEqual(
            self.requestor._http._default_headers["session_header"],
            custom_header,
        )
        self.assertEqual(await self.requestor.request("https://reddit.com"), override)
