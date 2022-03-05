"""Prepare py.test."""
import asyncio
import json
import os
from base64 import b64encode
from datetime import datetime

import pytest
from vcr import VCR
from vcr.persisters.filesystem import FilesystemPersister
from vcr.serialize import deserialize, serialize


# Prevent calls to sleep
async def _sleep(*args):
    raise Exception("Call to sleep")


asyncio.sleep = _sleep


def b64_string(input_string):
    """Return a base64 encoded string (not bytes) from input_string."""
    return b64encode(input_string.encode("utf-8")).decode("utf-8")


def env_default(key):
    """Return environment variable or placeholder string."""
    return os.environ.get(
        f"PRAWCORE_{key.upper()}",
        "http://localhost:8080" if key == "redirect_uri" else f"fake_{key}",
    )


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
    try:
        token = json.loads(body)["refresh_token"]
        response["body"]["string"] = response["body"]["string"].replace(
            token.encode("utf-8"), b"<REFRESH_TOKEN>"
        )
        placeholders["refresh_token"] = token
    except (KeyError, TypeError, ValueError):
        pass
    return response


def serialize_dict(data: dict):
    """This is to filter out buffered readers."""
    new_dict = {}
    for key, value in data.items():
        if key == "file":
            new_dict[key] = serialize_file(value.name)
        elif isinstance(value, dict):
            new_dict[key] = serialize_dict(value)
        elif isinstance(value, list):
            new_dict[key] = serialize_list(value)
        else:
            new_dict[key] = value
    return new_dict


def serialize_file(file_name):
    with open(file_name, "rb") as f:
        return f.read().decode("utf-8", "replace")


def serialize_list(data: list):
    """List serializer."""
    new_list = []
    for item in data:
        if isinstance(item, dict):
            new_list.append(serialize_dict(item))
        elif isinstance(item, list):
            new_list.append(serialize_list(item))
        elif isinstance(item, tuple):
            if item[0] == "file":
                item = (item[0], serialize_file(item[1].name))
            new_list.append(item)
        else:
            new_list.append(item)
    return new_list


def two_factor_callback():
    """Return an OTP code."""
    return None


placeholders = {
    x: env_default(x)
    for x in (
        "client_id client_secret password permanent_grant_code temporary_grant_code"
        " redirect_uri refresh_token user_agent username"
    ).split()
}

placeholders["BASIC_AUTH"] = b64_string(
    f"{placeholders['client_id']}:{placeholders['client_secret']}"
)


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
        for replacement, value in [
            (v, f"<{k.upper()}>") for k, v in placeholders.items()
        ]:
            cassette_content = cassette_content.replace(value, replacement)
        cassette = deserialize(cassette_content, serializer)
        return cassette

    @staticmethod
    def save_cassette(cassette_path, cassette_dict, serializer):
        """Save the cassette."""
        data = serialize(cassette_dict, serializer)
        for replacement, value in [
            (f"<{k.upper()}>", v) for k, v in placeholders.items()
        ]:
            data = data.replace(value, replacement)
        dirname, filename = os.path.split(cassette_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(cassette_path, "w") as f:
            f.write(data)


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


vcr = VCR(
    before_record_response=filter_access_token,
    cassette_library_dir="tests/integration/cassettes",
    match_on=["uri", "method"],
    path_transformer=VCR.ensure_suffix(".json"),
    serializer="custom_serializer",
)
vcr.register_serializer("custom_serializer", CustomSerializer)
vcr.register_persister(CustomPersister)


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


class Placeholders:
    def __init__(self, _dict):
        self.__dict__ = _dict


def pytest_configure():
    pytest.placeholders = Placeholders(placeholders)
