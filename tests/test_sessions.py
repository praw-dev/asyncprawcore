"""Test for asyncprawcore.Sessions module."""
import asyncio
import logging
from json import dumps

import asynctest
from aiohttp.web import HTTPRequestTimeout
from mock import patch
from testfixtures import LogCapture

import asyncprawcore
from asyncprawcore.exceptions import RequestException
from .conftest import (
    AsyncMock,
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    REFRESH_TOKEN,
    USERNAME,
    VCR,
)


class InvalidAuthorizer(asyncprawcore.Authorizer):
    def __init__(self):
        requestor = asyncprawcore.requestor.Requestor("asyncprawcore:test (by /u/bboe)")

        super(InvalidAuthorizer, self).__init__(
            asyncprawcore.TrustedAuthenticator(requestor, CLIENT_ID, CLIENT_SECRET)
        )

    def is_valid(self):
        return False


async def client_authorizer():
    requestor = asyncprawcore.requestor.Requestor("asyncprawcore:test (by /u/bboe)")

    authenticator = asyncprawcore.TrustedAuthenticator(
        requestor, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.Authorizer(authenticator, REFRESH_TOKEN)
    await authorizer.refresh()
    return authorizer


async def readonly_authorizer(refresh=True):
    requestor = asyncprawcore.requestor.Requestor("asyncprawcore:test (by /u/bboe)")
    authenticator = asyncprawcore.TrustedAuthenticator(
        requestor, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
    if refresh:
        await authorizer.refresh()
    return authorizer


async def script_authorizer():
    requestor = asyncprawcore.requestor.Requestor("asyncprawcore:test (by /u/bboe)")
    authenticator = asyncprawcore.TrustedAuthenticator(
        requestor, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.ScriptAuthorizer(authenticator, USERNAME, PASSWORD)
    await authorizer.refresh()
    return authorizer


class SessionTest(asynctest.TestCase):
    async def setUp(self) -> None:
        self.requestor = asyncprawcore.requestor.Requestor(
            "asyncprawcore:test (by /u/bboe)"
        )

    async def tearDown(self) -> None:
        await self.requestor.close()
        if hasattr(self, "session"):
            await self.session.close()

    async def test_close(self):
        authorizer = await readonly_authorizer(refresh=False)
        await asyncprawcore.Session(authorizer).close()

    async def test_context_manager(self):
        async with asyncprawcore.Session(
            await readonly_authorizer(refresh=False)
        ) as session:
            self.assertIsInstance(session, asyncprawcore.Session)

    def test_init__without_authenticator(self):
        self.assertRaises(asyncprawcore.InvalidInvocation, asyncprawcore.Session, None)

    def test_init__with_device_id_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator)
        asyncprawcore.Session(authorizer)

    def test_init__with_implicit_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        authorizer = asyncprawcore.ImplicitAuthorizer(authenticator, None, 0, "")
        asyncprawcore.Session(authorizer)

    @patch("aiohttp.ClientSession")
    async def test_request__connection_error_retry(self, mock_session):
        session_instance = mock_session.return_value
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

            authorizer = await readonly_authorizer()
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
            with self.assertRaises(RequestException) as context_manager:
                await asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(3, session_instance.request.call_count)

    async def test_request__get(self):
        with VCR.use_cassette("Session_request__get"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            params = {"limit": 100, "bool_param": True}
            response = await self.session.request("GET", "/", params=params)
        self.assertIsInstance(response, dict)
        self.assertEqual(2, len(params))
        self.assertEqual("Listing", response["kind"])

    async def test_request__patch(self):
        with VCR.use_cassette(
            "Session_request__patch",
            match_requests_on=["method", "uri", "json-body"],
        ):
            self.session = asyncprawcore.Session(await script_authorizer())
            json = {"lang": "ja", "num_comments": 123}
            response = await self.session.request(
                "PATCH", "/api/v1/me/prefs", json=json
            )
            self.assertEqual("ja", response["lang"])
            self.assertEqual(123, response["num_comments"])

    async def test_request__post(self):
        with VCR.use_cassette("Session_request__post"):
            session = asyncprawcore.Session(await script_authorizer())
            data = {
                "kind": "self",
                "sr": "asyncpraw",
                "text": "Test!",
                "title": "A Test from asyncprawcore.",
            }
            key_count = len(data)
            response = await session.request("POST", "/api/submit", data=data)
            self.assertIn("a_test_from_asyncprawcore", response["json"]["data"]["url"])
            self.assertEqual(key_count, len(data))  # Ensure data is untouched

    async def test_request__post__with_files(self):
        with VCR.use_cassette("Session_request__post__with_files", match_on=["uri"]):
            session = asyncprawcore.Session(await script_authorizer())
            with open("./tests/files/white-square.png", "rb") as fp:
                files = {"file": fp}
                data = {"test": "data"}
                response = await session.request(
                    "POST", "/r/asyncpraw/api/upload_sr_img", files=files, data=data
                )
            self.assertIn("img_src", response)

    async def test_request__raw_json(self):
        with VCR.use_cassette("Session_request__raw_json"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            response = await self.session.request(
                "GET",
                "/r/reddit_api_test/comments/45xjdr/want_raw_json_test/",
            )
        self.assertEqual(
            "WANT_RAW_JSON test: < > &",
            response[0]["data"]["children"][0]["data"]["title"],
        )

    async def test_request__bad_gateway(self):
        with VCR.use_cassette("Session_request__bad_gateway"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
            self.assertEqual(502, context_manager.exception.response.status)

    async def test_request__bad_json(self):
        with VCR.use_cassette("Session_request__bad_json"):
            self.session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.BadJSON) as context_manager:
                await self.session.request("GET", "/")
            self.assertEqual(17512, context_manager.exception.response.content_length)

    async def test_request__bad_request(self):
        with VCR.use_cassette("Session_request__bad_request"):
            self.session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.BadRequest) as context_manager:
                await self.session.request(
                    "PUT",
                    "/api/v1/me/friends/spez",
                    data='{"note": "asyncprawcore"}',
                )
            self.assertIn("reason", await context_manager.exception.response.json())

    async def test_request__cloudflair_connection_timed_out(self):
        with VCR.use_cassette("Session_request__cloudflair_connection_timed_out"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
            self.assertEqual(522, context_manager.exception.response.status)

    async def test_request__cloudflair_unknown_error(self):
        with VCR.use_cassette("Session_request__cloudflair_unknown_error"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
            self.assertEqual(520, context_manager.exception.response.status)

    async def test_request__conflict(self):
        with VCR.use_cassette("Session_request__conflict"):
            session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.Conflict) as context_manager:
                await session.request(
                    "POST",
                    "/api/multi/copy/",
                    data={
                        "display_name": "sfwpornnetwork",
                        "from": "/user/kjoneslol/m/sfwpornnetwork",
                        "to": f"user/{USERNAME}/m/sfwpornnetwork/",
                    },
                )
            self.assertEqual(409, context_manager.exception.response.status)

    async def test_request__created(self):
        with VCR.use_cassette("Session_request__created"):
            self.session = asyncprawcore.Session(await script_authorizer())
            response = await self.session.request(
                "PUT", "/api/v1/me/friends/spez", data="{}"
            )
            self.assertIn("name", response)

    async def test_request__forbidden(self):
        with VCR.use_cassette("Session_request__forbidden"):
            self.session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.Forbidden):
                await self.session.request("GET", "/user/spez/gilded/given")

    async def test_request__gateway_timeout(self):
        with VCR.use_cassette("Session_request__gateway_timeout"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
            self.assertEqual(504, context_manager.exception.response.status)

    async def test_request__internal_server_error(self):
        with VCR.use_cassette("Session_request__internal_server_error"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
            self.assertEqual(500, context_manager.exception.response.status)

    async def test_request__no_content(self):
        with VCR.use_cassette("Session_request__no_content"):
            self.session = asyncprawcore.Session(await script_authorizer())
            response = await self.session.request("DELETE", "/api/v1/me/friends/spez")
            self.assertIsNone(response)

    async def test_request__not_found(self):
        with VCR.use_cassette("Session_request__not_found"):
            self.session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.NotFound):
                await self.session.request("GET", "/r/cricket/wiki/invalid")

    async def test_request__okay_with_0_byte_content(self):
        with VCR.use_cassette(
            "Session_request__okay_with_0_byte_content", match_on=["method"]
        ):
            self.session = asyncprawcore.Session(await script_authorizer())
            data = {"model": dumps({"name": "test"})}
            path = f"/api/multi/user/{USERNAME}/m/test"
            response = await self.session.request("DELETE", path, data=data)
            self.assertEqual("", response)

    @patch("aiohttp.ClientSession")
    async def test_request__read_timeout_retry(self, mock_session):
        self.session_instance = mock_session.return_value
        self.session_instance.request.return_value = asyncio.Future()
        self.session_instance.request.return_value.set_result(
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

        authorizer = await readonly_authorizer()
        self.session_instance.request.reset_mock()

        exception = HTTPRequestTimeout()
        self.session_instance.request.side_effect = exception

        expected = (
            "asyncprawcore",
            "WARNING",
            "Retrying due to <HTTPRequestTimeout Request Timeout not prepared> status: "
            "GET https://oauth.reddit.com/",
        )

        with LogCapture(level=logging.WARNING) as log_capture:
            with self.assertRaises(RequestException) as context_manager:
                await asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(3, self.session_instance.request.call_count)

    async def test_request__redirect(self):
        with VCR.use_cassette("Session_request__redirect"):
            session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.Redirect) as context_manager:
                await session.request("GET", "/r/random")
            self.assertTrue(context_manager.exception.path.startswith("/r/"))

    async def test_request__service_unavailable(self):
        with VCR.use_cassette("Session_request__service_unavailable"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            with self.assertRaises(asyncprawcore.ServerError) as context_manager:
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
                await self.session.request("GET", "/")
            self.assertEqual(503, context_manager.exception.response.status)

    async def test_request__too_large(self):
        with VCR.use_cassette(
            "Session_request__too_large",
            match_requests_on=["uri", "method"],  # , serializer="yaml",
        ):
            session = asyncprawcore.Session(await script_authorizer())
            with self.assertRaises(asyncprawcore.TooLarge) as context_manager:
                await session.request(
                    "POST",
                    "/r/asyncpraw/api/upload_sr_img",
                    files={"file": open("./tests/files/too_large.jpg", "rb")},
                )
            self.assertEqual(413, context_manager.exception.response.status)

    async def test_request__unavailable_for_legal_reasons(self):
        with VCR.use_cassette("Session_request__unavailable_for_legal_reasons"):
            authenticator = asyncprawcore.UntrustedAuthenticator(
                self.requestor, CLIENT_ID
            )
            authorizer = asyncprawcore.ImplicitAuthorizer(authenticator, None, 0, "")
            self.session = asyncprawcore.Session(authorizer)
            exception_class = asyncprawcore.UnavailableForLegalReasons
            with self.assertRaises(exception_class) as context_manager:
                await self.session.request("GET", "/")
            self.assertEqual(451, context_manager.exception.response.status)

    async def test_request__unsupported_media_type(self):
        with VCR.use_cassette(
            "Session_request__unsupported_media_type",
            match_requests_on=["uri", "method"],
        ):
            session = asyncprawcore.Session(await script_authorizer())
            exception_class = asyncprawcore.SpecialError
            data = {
                "content": "type: submission\naction: upvote",
                "page": "config/automoderator",
            }
            with self.assertRaises(exception_class) as context_manager:
                await session.request("POST", "r/asyncpraw/api/wiki/edit/", data=data)
            self.assertEqual(415, context_manager.exception.response.status)

    async def test_request__with_insufficent_scope(self):
        with VCR.use_cassette("Session_request__with_insufficient_scope"):
            self.session = asyncprawcore.Session(await client_authorizer())
            with self.assertRaises(asyncprawcore.InsufficientScope):
                await self.session.request("GET", "/api/v1/me")

    async def test_request__with_invalid_access_token(self):
        self.authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, CLIENT_ID
        )
        self.authorizer = asyncprawcore.ImplicitAuthorizer(
            self.authenticator, None, 0, ""
        )
        self.session = asyncprawcore.Session(self.authorizer)

        with VCR.use_cassette("Session_request__with_invalid_access_token"):
            self.session._authorizer.access_token = "invalid"
            with self.assertRaises(asyncprawcore.InvalidToken):
                await self.session.request("get", "/")

    async def test_request__with_invalid_access_token__retry(self):
        with VCR.use_cassette("Session_request__with_invalid_access_token__retry"):
            self.session = asyncprawcore.Session(await readonly_authorizer())
            self.session._authorizer.access_token += "invalid"
            response = await self.session.request("GET", "/")
        self.assertIsInstance(response, dict)

    async def test_request__with_invalid_authorizer(self):
        self.session = asyncprawcore.Session(InvalidAuthorizer())
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            await self.session.request("get", "/")


class SessionFunctionTest(asynctest.TestCase):
    async def test_session(self):
        session = asyncprawcore.session(InvalidAuthorizer())
        try:
            self.assertIsInstance(session, asyncprawcore.Session)
        finally:
            await session.close()
