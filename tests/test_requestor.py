"""Test for asyncprawcore.requestor.Requestor class."""
import pickle

import asyncprawcore
import unittest
from mock import patch, Mock
from asyncprawcore import RequestException


class RequestorTest(unittest.TestCase):
    def test_initialize(self):
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        self.assertEqual(
            "asyncprawcore:test (by /u/bboe) asyncprawcore/{}".format(
                asyncprawcore.__version__
            ),
            requestor._http.headers["User-Agent"],
        )

    def test_initialize__failures(self):
        for agent in [None, "shorty"]:
            self.assertRaises(
                asyncprawcore.InvalidInvocation, asyncprawcore.Requestor, agent
            )

    @patch("requests.Session")
    def test_request__wrap_request_exceptions(self, mock_session):
        exception = Exception("asyncprawcore wrap_request_exceptions")
        session_instance = mock_session.return_value
        session_instance.request.side_effect = exception
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        with self.assertRaises(
            asyncprawcore.RequestException
        ) as context_manager:
            requestor.request("get", "http://a.b", data="bar")
        self.assertIsInstance(context_manager.exception, RequestException)
        self.assertIs(exception, context_manager.exception.original_exception)
        self.assertEqual(
            ("get", "http://a.b"), context_manager.exception.request_args
        )
        self.assertEqual(
            {"data": "bar"}, context_manager.exception.request_kwargs
        )

    def test_request__use_custom_session(self):
        override = "REQUEST OVERRIDDEN"
        custom_header = "CUSTOM SESSION HEADER"
        headers = {"session_header": custom_header}
        attrs = {"request.return_value": override, "headers": headers}
        session = Mock(**attrs)

        requestor = asyncprawcore.Requestor(
            "asyncprawcore:test (by /u/bboe)", session=session
        )

        self.assertEqual(
            "asyncprawcore:test (by /u/bboe) asyncprawcore/{}".format(
                asyncprawcore.__version__
            ),
            requestor._http.headers["User-Agent"],
        )
        self.assertEqual(
            requestor._http.headers["session_header"], custom_header
        )

        self.assertEqual(requestor.request("https://reddit.com"), override)

    def test_pickle(self):
        requestor = asyncprawcore.Requestor("asyncprawcore:test (by /u/bboe)")
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            pickle.loads(pickle.dumps(requestor, protocol=protocol))
