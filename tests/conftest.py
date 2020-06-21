"""Constants for the asyncprawcore test suite."""

import os
from vcr import VCR

CLIENT_ID = os.environ.get("PRAWCORE_CLIENT_ID", "fake_client_id")
CLIENT_SECRET = os.environ.get("PRAWCORE_CLIENT_SECRET", "fake_client_secret")
PASSWORD = os.environ.get("PRAWCORE_PASSWORD", "fake_password")
PERMANENT_GRANT_CODE = os.environ.get(
    "PRAWCORE_PERMANENT_GRANT_CODE", "fake_perm_code"
)
REDIRECT_URI = os.environ.get("PRAWCORE_REDIRECT_URI", "http://localhost:8080")
REFRESH_TOKEN = os.environ.get("PRAWCORE_REFRESH_TOKEN", "fake_refresh_token")
TEMPORARY_GRANT_CODE = os.environ.get(
    "PRAWCORE_TEMPORARY_GRANT_CODE", "fake_temp_code"
)
USERNAME = os.environ.get("PRAWCORE_USERNAME", "fake_username")


class CustomVCR(VCR):
    """Derived from VCR to make setting paths easier."""

    def use_cassette(self, path="", **kwargs):
        """Use a cassette."""
        path += ".json"
        return super().use_cassette(path, **kwargs)


placeholders = [
    tuple(reversed(placeholder))
    for placeholder in [
        ("<CLIENT_ID>", CLIENT_ID),
        ("<CLIENT_SECRET>", CLIENT_SECRET),
        ("<PASSWORD>", PASSWORD),
        ("<PERM_CODE>", PERMANENT_GRANT_CODE),
        ("<REFRESH_TOKEN>", REFRESH_TOKEN),
        ("<TEMP_CODE>", TEMPORARY_GRANT_CODE),
        ("<USERNAME>", USERNAME),
    ]
]

VCR = CustomVCR(
    serializer="json",
    cassette_library_dir="tests/cassettes",
    match_on=["uri", "method"],
    filter_headers=placeholders,
    filter_post_data_parameters=placeholders,
    filter_query_parameters=placeholders,
)


class AsyncMock:
    """Class to assist making asynchronous mocks simpler to write."""

    def __init__(self, status, response_dict, headers):
        """Initialize the class with return status, response-dict and headers."""
        self.status = status
        self.response_dict = response_dict
        self.headers = headers

    async def json(self):
        """Mock the json of ClientSession.request."""
        return self.response_dict
