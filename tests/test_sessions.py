"""Test for asyncprawcore.Sessions module."""
import logging
from json import dumps

import asyncprawcore
import unittest
from betamax import Betamax
from mock import Mock, patch
from asyncprawcore.exceptions import RequestException
from requests.exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ReadTimeout,
)
from testfixtures import LogCapture

from .config import (
    CLIENT_ID,
    CLIENT_SECRET,
    REFRESH_TOKEN,
    REQUESTOR,
    PASSWORD,
    USERNAME,
)


class InvalidAuthorizer(asyncprawcore.Authorizer):
    def __init__(self):
        super(InvalidAuthorizer, self).__init__(
            asyncprawcore.TrustedAuthenticator(
                REQUESTOR, CLIENT_ID, CLIENT_SECRET
            )
        )

    def is_valid(self):
        return False


def client_authorizer():
    authenticator = asyncprawcore.TrustedAuthenticator(
        REQUESTOR, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.Authorizer(authenticator, REFRESH_TOKEN)
    authorizer.refresh()
    return authorizer


def readonly_authorizer(refresh=True, requestor=REQUESTOR):
    authenticator = asyncprawcore.TrustedAuthenticator(
        requestor, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
    if refresh:
        authorizer.refresh()
    return authorizer


def script_authorizer():
    authenticator = asyncprawcore.TrustedAuthenticator(
        REQUESTOR, CLIENT_ID, CLIENT_SECRET
    )
    authorizer = asyncprawcore.ScriptAuthorizer(
        authenticator, USERNAME, PASSWORD
    )
    authorizer.refresh()
    return authorizer


class SessionTest(unittest.TestCase):
    def test_close(self):
        asyncprawcore.Session(readonly_authorizer(refresh=False)).close()

    def test_context_manager(self):
        with asyncprawcore.Session(
            readonly_authorizer(refresh=False)
        ) as session:
            self.assertIsInstance(session, asyncprawcore.Session)

    def test_init__without_authenticator(self):
        self.assertRaises(
            asyncprawcore.InvalidInvocation, asyncprawcore.Session, None
        )

    def test_init__with_device_id_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
        authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator)
        asyncprawcore.Session(authorizer)

    def test_init__with_implicit_authorizer(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
        authorizer = asyncprawcore.ImplicitAuthorizer(
            authenticator, None, 0, ""
        )
        asyncprawcore.Session(authorizer)

    @patch("requests.Session")
    def test_request__chunked_encoding_retry(self, mock_session):
        session_instance = mock_session.return_value

        # Handle Auth
        response_dict = {"access_token": "", "expires_in": 99, "scope": ""}
        session_instance.request.return_value = Mock(
            headers={}, json=lambda: response_dict, status_code=200
        )
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        authorizer = readonly_authorizer(requestor=requestor)
        session_instance.request.reset_mock()

        # Fail on subsequent request
        exception = ChunkedEncodingError()
        session_instance.request.side_effect = exception

        expected = (
            "asyncprawcore",
            "WARNING",
            "Retrying due to ChunkedEncodingError() status: GET "
            "https://oauth.reddit.com/",
        )

        with LogCapture(level=logging.WARNING) as log_capture:
            with self.assertRaises(RequestException) as context_manager:
                asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(3, session_instance.request.call_count)

    @patch("requests.Session")
    def test_request__connection_error_retry(self, mock_session):
        session_instance = mock_session.return_value

        # Handle Auth
        response_dict = {"access_token": "", "expires_in": 99, "scope": ""}
        session_instance.request.return_value = Mock(
            headers={}, json=lambda: response_dict, status_code=200
        )
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        authorizer = readonly_authorizer(requestor=requestor)
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

        with LogCapture(level=logging.WARNING) as log_capture:
            with self.assertRaises(RequestException) as context_manager:
                asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(3, session_instance.request.call_count)

    def test_request__get(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__get"):
            session = asyncprawcore.Session(readonly_authorizer())
            params = {"limit": 100}
            response = session.request("GET", "/", params=params)
        self.assertIsInstance(response, dict)
        self.assertEqual(1, len(params))
        self.assertEqual("Listing", response["kind"])

    def test_request__patch(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__patch",
            match_requests_on=["method", "uri", "json-body"],
        ):
            session = asyncprawcore.Session(script_authorizer())
            json = {"lang": "ja", "num_comments": 123}
            response = session.request("PATCH", "/api/v1/me/prefs", json=json)
            self.assertEqual("ja", response["lang"])
            self.assertEqual(123, response["num_comments"])

    def test_request__post(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__post"):
            session = asyncprawcore.Session(script_authorizer())
            data = {
                "kind": "self",
                "sr": "reddit_api_test",
                "text": "Test!",
                "title": "A Test from asyncprawcore.",
            }
            key_count = len(data)
            response = session.request("POST", "/api/submit", data=data)
            self.assertIn(
                "a_test_from_asyncprawcore", response["json"]["data"]["url"]
            )
            self.assertEqual(key_count, len(data))  # Ensure data is untouched

    def test_request__post__with_files(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__post__with_files",
            match_requests_on=["uri", "method"],
        ):
            session = asyncprawcore.Session(script_authorizer())
            data = {"upload_type": "header"}
            with open("tests/files/white-square.png", "rb") as fp:
                files = {"file": fp}
                response = session.request(
                    "POST",
                    "/r/reddit_api_test/api/upload_sr_img",
                    data=data,
                    files=files,
                )
            self.assertIn("img_src", response)

    def test_request__raw_json(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__raw_json"):
            session = asyncprawcore.Session(readonly_authorizer())
            response = session.request(
                "GET",
                ("/r/reddit_api_test/comments/" "45xjdr/want_raw_json_test/"),
            )
        self.assertEqual(
            "WANT_RAW_JSON test: < > &",
            response[0]["data"]["children"][0]["data"]["title"],
        )

    def test_request__bad_gateway(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__bad_gateway"):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
            self.assertEqual(
                502, context_manager.exception.response.status_code
            )

    def test_request__bad_json(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__bad_json"):
            session = asyncprawcore.Session(script_authorizer())
            with self.assertRaises(asyncprawcore.BadJSON) as context_manager:
                session.request("GET", "/")
            self.assertEqual(
                92, len(context_manager.exception.response.content)
            )

    def test_request__bad_request(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__bad_request"):
            session = asyncprawcore.Session(script_authorizer())
            with self.assertRaises(
                asyncprawcore.BadRequest
            ) as context_manager:
                session.request(
                    "PUT",
                    "/api/v1/me/friends/spez",
                    data='{"note": "asyncprawcore"}',
                )
            self.assertIn("reason", context_manager.exception.response.json())

    def test_request__cloudflair_connection_timed_out(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__cloudflair_connection_timed_out"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
                session.request("GET", "/")
                session.request("GET", "/")
            self.assertEqual(
                522, context_manager.exception.response.status_code
            )

    def test_request__cloudflair_unknown_error(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__cloudflair_unknown_error"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
                session.request("GET", "/")
                session.request("GET", "/")
            self.assertEqual(
                520, context_manager.exception.response.status_code
            )

    def test_request__conflict(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__conflict"):
            session = asyncprawcore.Session(script_authorizer())
            previous = "f0214574-430d-11e7-84ca-1201093304fa"
            with self.assertRaises(asyncprawcore.Conflict) as context_manager:
                session.request(
                    "POST",
                    "/r/ThirdRealm/api/wiki/edit",
                    data={
                        "content": "New text",
                        "page": "index",
                        "previous": previous,
                    },
                )
            self.assertEqual(
                409, context_manager.exception.response.status_code
            )

    def test_request__created(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__created"):
            session = asyncprawcore.Session(script_authorizer())
            response = session.request(
                "PUT", "/api/v1/me/friends/spez", data="{}"
            )
            self.assertIn("name", response)

    def test_request__forbidden(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__forbidden"):
            session = asyncprawcore.Session(script_authorizer())
            self.assertRaises(
                asyncprawcore.Forbidden,
                session.request,
                "GET",
                "/user/spez/gilded/given",
            )

    def test_request__gateway_timeout(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__gateway_timeout"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
            self.assertEqual(
                504, context_manager.exception.response.status_code
            )

    def test_request__internal_server_error(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__internal_server_error"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
            self.assertEqual(
                500, context_manager.exception.response.status_code
            )

    def test_request__no_content(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__no_content"):
            session = asyncprawcore.Session(script_authorizer())
            response = session.request("DELETE", "/api/v1/me/friends/spez")
            self.assertIsNone(response)

    def test_request__not_found(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__not_found"):
            session = asyncprawcore.Session(script_authorizer())
            self.assertRaises(
                asyncprawcore.NotFound,
                session.request,
                "GET",
                "/r/reddit_api_test/wiki/invalid",
            )

    def test_request__okay_with_0_byte_content(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__okay_with_0_byte_content"
        ):
            session = asyncprawcore.Session(script_authorizer())
            data = {"model": dumps({"name": "redditdev"})}
            path = "/api/multi/user/{}/m/praw_x5g968f66a/r/redditdev".format(
                USERNAME
            )
            response = session.request("DELETE", path, data=data)
            self.assertEqual("", response)

    @patch("requests.Session")
    def test_request__read_timeout_retry(self, mock_session):
        session_instance = mock_session.return_value

        # Handle Auth
        response_dict = {"access_token": "", "expires_in": 99, "scope": ""}
        session_instance.request.return_value = Mock(
            headers={}, json=lambda: response_dict, status_code=200
        )
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        authorizer = readonly_authorizer(requestor=requestor)
        session_instance.request.reset_mock()

        # Fail on subsequent request
        exception = ReadTimeout()
        session_instance.request.side_effect = exception

        expected = (
            "asyncprawcore",
            "WARNING",
            "Retrying due to ReadTimeout() status: GET "
            "https://oauth.reddit.com/",
        )

        with LogCapture(level=logging.WARNING) as log_capture:
            with self.assertRaises(RequestException) as context_manager:
                asyncprawcore.Session(authorizer).request("GET", "/")
            log_capture.check(expected, expected)
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(3, session_instance.request.call_count)

    def test_request__redirect(self):
        with Betamax(REQUESTOR).use_cassette("Session_request__redirect"):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(asyncprawcore.Redirect) as context_manager:
                session.request("GET", "/r/random")
            self.assertTrue(context_manager.exception.path.startswith("/r/"))

    def test_request__service_unavailable(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__service_unavailable"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            with self.assertRaises(
                asyncprawcore.ServerError
            ) as context_manager:
                session.request("GET", "/")
                session.request("GET", "/")
                session.request("GET", "/")
            self.assertEqual(
                503, context_manager.exception.response.status_code
            )

    def test_request__too_large(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__too_large", match_requests_on=["uri", "method"]
        ):
            session = asyncprawcore.Session(script_authorizer())
            data = {"upload_type": "header"}
            with open("tests/files/too_large.jpg", "rb") as fp:
                files = {"file": fp}
                with self.assertRaises(
                    asyncprawcore.TooLarge
                ) as context_manager:
                    session.request(
                        "POST",
                        "/r/reddit_api_test/api/upload_sr_img",
                        data=data,
                        files=files,
                    )
            self.assertEqual(
                413, context_manager.exception.response.status_code
            )

    def test_request__unavailable_for_legal_reasons(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__unavailable_for_legal_reasons"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            exception_class = asyncprawcore.UnavailableForLegalReasons
            with self.assertRaises(exception_class) as context_manager:
                session.request("GET", "/")
            self.assertEqual(
                451, context_manager.exception.response.status_code
            )

    def test_request__unsupported_media_type(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__unsupported_media_type"
        ):
            session = asyncprawcore.Session(script_authorizer())
            exception_class = asyncprawcore.SpecialError
            data = {
                "content": "type: submission\naction: upvote",
                "page": "config/automoderator",
            }
            with self.assertRaises(exception_class) as context_manager:
                session.request("POST", "r/ttft/api/wiki/edit/", data=data)
            self.assertEqual(
                415, context_manager.exception.response.status_code
            )

    def test_request__with_insufficent_scope(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__with_insufficient_scope"
        ):
            session = asyncprawcore.Session(client_authorizer())
            self.assertRaises(
                asyncprawcore.InsufficientScope,
                session.request,
                "GET",
                "/api/v1/me",
            )

    def test_request__with_invalid_access_token(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
        authorizer = asyncprawcore.ImplicitAuthorizer(
            authenticator, None, 0, ""
        )
        session = asyncprawcore.Session(authorizer)

        with Betamax(REQUESTOR).use_cassette(
            "Session_request__with_invalid_access_token"
        ):
            session._authorizer.access_token = "invalid"
            self.assertRaises(
                asyncprawcore.InvalidToken, session.request, "get", "/"
            )

    def test_request__with_invalid_access_token__retry(self):
        with Betamax(REQUESTOR).use_cassette(
            "Session_request__with_invalid_access_token__retry"
        ):
            session = asyncprawcore.Session(readonly_authorizer())
            session._authorizer.access_token += "invalid"
            response = session.request("GET", "/")
        self.assertIsInstance(response, dict)

    def test_request__with_invalid_authorizer(self):
        session = asyncprawcore.Session(InvalidAuthorizer())
        self.assertRaises(
            asyncprawcore.InvalidInvocation, session.request, "get", "/"
        )


class SessionFunctionTest(unittest.TestCase):
    def test_session(self):
        self.assertIsInstance(
            asyncprawcore.session(InvalidAuthorizer()), asyncprawcore.Session
        )
