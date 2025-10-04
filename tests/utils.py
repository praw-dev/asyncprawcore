"""Pytest utils for integration tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vcr.persisters.filesystem import FilesystemPersister
from vcr.serialize import deserialize, serialize

from tests.conftest import placeholders as _placeholders


def ensure_integration_test(cassette):  # pragma: no cover
    """Ensure test is being run is actually an integration test and error if not."""
    if cassette.write_protected:  # pragma: no cover
        is_integration_test = cassette.play_count > 0
        action = "play back"
    else:
        is_integration_test = cassette.dirty
        action = "record"
    message = f"Cassette did not {action} any requests. This test can be a unit test."
    assert is_integration_test, message


def filter_access_token(response):  # pragma: no cover
    """Add VCR callback to filter access token."""
    request_uri = response["url"]
    if "api/v1/access_token" not in request_uri or response["status"]["code"] != 200:
        return response
    body = response["body"]["string"].decode()
    json_body = json.loads(body)
    for token_key in ["access", "refresh"]:
        try:
            token = json_body[f"{token_key}_token"]
        except (KeyError, TypeError, ValueError):
            continue
        response["body"]["string"] = response["body"]["string"].replace(
            token.encode("utf-8"), f"<{token_key.upper()}_TOKEN>".encode()
        )
        _placeholders[f"{token_key}_token"] = token
    return response


class CustomPersister(FilesystemPersister):
    """Custom persister to handle placeholders."""

    additional_placeholders = {}

    @classmethod
    def add_additional_placeholders(cls, placeholders: dict[str, str]):  # pragma: no cover
        """Add additional placeholders."""
        cls.additional_placeholders.update(placeholders)

    @classmethod
    def clear_additional_placeholders(cls):  # pragma: no cover
        """Clear additional placeholders."""
        cls.additional_placeholders = {}

    @classmethod
    def load_cassette(cls, cassette_path, serializer):  # pragma: no cover
        """Load cassette."""
        try:
            with Path(cassette_path).open() as f:
                cassette_content = f.read()
        except OSError as error:
            msg = "Cassette not found."
            raise ValueError(msg) from error
        for replacement, value in [
            (v, f"<{k.upper()}>") for k, v in {**cls.additional_placeholders, **_placeholders}.items()
        ]:
            cassette_content = cassette_content.replace(value, replacement)
        return deserialize(cassette_content, serializer)

    @classmethod
    def save_cassette(cls, cassette_path, cassette_dict, serializer):  # pragma: no cover
        """Save cassette."""
        cassette_path = Path(cassette_path)
        data = serialize(cassette_dict, serializer)
        for replacement, value in [
            (f"<{k.upper()}>", v) for k, v in {**cls.additional_placeholders, **_placeholders}.items()
        ]:
            data = data.replace(value, replacement)
        dirname = cassette_path.parent
        if dirname and not dirname.exists():
            dirname.mkdir(parents=True)
        with cassette_path.open("w") as f:
            f.write(data)


class CustomSerializer:
    """Custom serializer to handle binary objects in dict."""

    @staticmethod
    def _serialize_file(file):  # pragma: no cover
        with Path(file.name).open("rb") as f:
            return f.read().decode("utf-8", "replace")

    @staticmethod
    def deserialize(cassette_string):
        return json.loads(cassette_string)

    @classmethod
    def _serialize_dict(cls, data: dict):  # pragma: no cover
        """This is to filter out buffered readers."""
        new_dict = {}
        for key, value in data.items():
            if key == "file":
                new_dict[key] = cls._serialize_file(value)
            elif isinstance(value, dict):
                new_dict[key] = cls._serialize_dict(value)
            elif isinstance(value, list):
                new_dict[key] = cls._serialize_list(value)
            else:
                new_dict[key] = value
        return new_dict

    @classmethod
    def _serialize_list(cls, data: list):  # pragma: no cover
        new_list = []
        for item in data:
            if isinstance(item, dict):
                new_list.append(cls._serialize_dict(item))
            elif isinstance(item, list):
                new_list.append(cls._serialize_list(item))
            elif isinstance(item, tuple):
                file = None
                if item[0] == "file":
                    file = (item[0], cls._serialize_file(item[1]))
                new_list.append(file or item)
            else:
                new_list.append(item)
        return new_list

    @classmethod
    def serialize(cls, cassette_dict):  # pragma: no cover
        """Serialize cassette."""
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        try:
            i = timestamp.rindex(".")
        except ValueError:
            pass
        else:
            timestamp = timestamp[:i]
        cassette_dict["recorded_at"] = timestamp
        return f"{json.dumps(cls._serialize_dict(cassette_dict), sort_keys=True, indent=2)}\n"
