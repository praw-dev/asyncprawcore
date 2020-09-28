"""Constants for the asyncprawcore test suite."""

import json
import os
from base64 import b64encode
from datetime import datetime
from vcr import VCR
from vcr.persisters.filesystem import FilesystemPersister
from vcr.serialize import deserialize, serialize


CLIENT_ID = os.environ.get("PRAWCORE_CLIENT_ID", "fake_client_id")
CLIENT_SECRET = os.environ.get("PRAWCORE_CLIENT_SECRET", "fake_client_secret")
PASSWORD = os.environ.get("PRAWCORE_PASSWORD", "fake_password")
PERMANENT_GRANT_CODE = os.environ.get("PRAWCORE_PERMANENT_GRANT_CODE", "fake_perm_code")
REDIRECT_URI = os.environ.get("PRAWCORE_REDIRECT_URI", "http://localhost:8080")
REFRESH_TOKEN = os.environ.get("PRAWCORE_REFRESH_TOKEN", "fake_refresh_token")
TEMPORARY_GRANT_CODE = os.environ.get("PRAWCORE_TEMPORARY_GRANT_CODE", "fake_temp_code")
USERNAME = os.environ.get("PRAWCORE_USERNAME", "fake_username")


def b64_string(input_string):
    """Return a base64 encoded string (not bytes) from input_string."""
    return b64encode(input_string.encode("utf-8")).decode("utf-8")


placeholders = [
    ("<CLIENT_ID>", CLIENT_ID),
    ("<CLIENT_SECRET>", CLIENT_SECRET),
    ("<PASSWORD>", PASSWORD),
    ("<PERM_CODE>", PERMANENT_GRANT_CODE),
    ("<REFRESH_TOKEN>", REFRESH_TOKEN),
    ("<TEMP_CODE>", TEMPORARY_GRANT_CODE),
    ("<USERNAME>", USERNAME),
    ("<BASIC_AUTH>", b64_string(f"{CLIENT_ID}:{CLIENT_SECRET}")),
]


def filter_access_token(response):
    """Add VCR callback to filter access token."""
    request_uri = response["url"]
    if "api/v1/access_token" not in request_uri or response["status"]["code"] != 200:
        return response
    body = response["body"]["string"].decode()
    try:
        token = json.loads(body)["access_token"]
        response["body"]["string"] = response["body"]["string"].replace(
            token.encode("utf-8"), b"<ACCESS_TOKEN>"
        )
        placeholders["access_token"] = token
    except (KeyError, TypeError, ValueError):
        pass
    return response


def serialize_list(data: list):
    """List serializer."""
    new_list = []
    for item in data:
        if isinstance(item, dict):
            new_list.append(serialize_dict(item))
        elif isinstance(item, list):
            new_list.append(serialize_list(item))
        else:
            new_list.append(item)
    return new_list


def serialize_dict(data: dict):
    """Filter out buffered readers."""
    new_dict = {}
    for key, value in data.items():
        if key == "file":
            continue  # skip files
        elif isinstance(value, dict):
            new_dict[key] = serialize_dict(value)
        elif isinstance(value, list):
            new_dict[key] = serialize_list(value)
        else:
            new_dict[key] = value
    return new_dict


class CustomSerializer(object):
    """Custom serializer for cassettes."""

    @staticmethod
    def serialize(cassette_dict):
        """Serialize cassette dict."""
        cassette_dict["recorded_at"] = datetime.now().isoformat()[:-7]
        return (
            f"{json.dumps(serialize_dict(cassette_dict), sort_keys=True, indent=2)}\n"
        )

    @staticmethod
    def deserialize(cassette_string):
        """Deserialize cassette string."""
        return json.loads(cassette_string)


class CustomPersister(FilesystemPersister):
    """Custom persiter for VCR."""

    @classmethod
    def load_cassette(cls, cassette_path, serializer):
        """Load the cassette."""
        try:
            with open(cassette_path) as f:
                cassette_content = f.read()
        except OSError:
            raise ValueError("Cassette not found.")
        for replacement, value in placeholders:
            cassette_content = cassette_content.replace(value, replacement)
        cassette = deserialize(cassette_content, serializer)
        return cassette

    @staticmethod
    def save_cassette(cassette_path, cassette_dict, serializer):
        """Save the cassette."""
        data = serialize(cassette_dict, serializer)
        for replacement, value in placeholders:
            data = data.replace(value, replacement)
        dirname, filename = os.path.split(cassette_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(cassette_path, "w") as f:
            f.write(data)


class CustomVCR(VCR):
    """Derived from VCR to make setting paths easier."""

    def use_cassette(self, path="", **kwargs):
        """Use a cassette."""
        path += ".json"
        return super().use_cassette(path, **kwargs)


VCR = CustomVCR(
    serializer="custom_serializer",
    cassette_library_dir="tests/cassettes",
    match_on=["uri", "method"],
    before_record_response=filter_access_token,
)
VCR.register_serializer("custom_serializer", CustomSerializer)
VCR.register_persister(CustomPersister)


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
