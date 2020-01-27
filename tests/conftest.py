"""Constants for the asyncprawcore test suite."""

import os
from base64 import b64encode
from vcr import VCR
from asyncprawcore import Requestor

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


REQUESTOR = Requestor("asyncprawcore:test (by /u/bboe)")


def b64_string(input_string):
    """Return a base64 encoded string (not bytes) from input_string."""
    return b64encode(input_string.encode("utf-8")).decode("utf-8")


class CustomVCR(VCR):
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
