"""asyncprawcore Integration test suite."""

import os
from pathlib import Path

import pytest
from vcr import VCR

from ..utils import (
    CustomPersister,
    CustomSerializer,
    ensure_integration_test,
    filter_access_token,
)

CASSETTES_PATH = Path("tests/integration/cassettes")
existing_cassettes = set()
used_cassettes = set()


class IntegrationTest:
    """Base class for Async PRAW integration tests."""

    @pytest.fixture(autouse=True, scope="session")
    def cassette_tracker(self):  # pragma: no cover
        """Track cassettes to ensure unused cassettes are not uploaded."""
        for cassette in CASSETTES_PATH.iterdir():
            existing_cassettes.add(str(cassette)[: cassette.name.rindex(".")])
        yield
        unused_cassettes = existing_cassettes - used_cassettes
        if unused_cassettes and os.getenv("ENSURE_NO_UNUSED_CASSETTES", "0") == "1":
            msg = f"The following cassettes are unused: {', '.join(unused_cassettes)}."
            raise AssertionError(msg)

    @pytest.fixture(autouse=True)
    def cassette(self, request, recorder, cassette_name):
        """Wrap a test in a VCR cassette."""
        kwargs = {}
        for marker in request.node.iter_markers("recorder_kwargs"):
            for key, value in marker.kwargs.items():
                #  Don't overwrite existing values since function markers are provided
                #  before class markers.
                kwargs.setdefault(key, value)
        with recorder.use_cassette(cassette_name, **kwargs) as cassette:
            yield cassette
            ensure_integration_test(cassette)
            used_cassettes.add(cassette_name)

    @pytest.fixture(autouse=True)
    def recorder(self):
        """Configure VCR."""
        vcr = VCR()
        vcr.before_record_response = filter_access_token
        vcr.cassette_library_dir = str(CASSETTES_PATH)
        vcr.decode_compressed_response = True
        vcr.match_on = ["uri", "method"]
        vcr.path_transformer = VCR.ensure_suffix(".json")
        vcr.register_persister(CustomPersister)
        vcr.register_serializer("custom_serializer", CustomSerializer)  # noqa: PLW2901
        vcr.serializer = "custom_serializer"
        yield vcr
        CustomPersister.additional_placeholders = {}

    @pytest.fixture
    def cassette_name(self, request, vcr_cassette_name):
        """Return the name of the cassette to use."""
        marker = request.node.get_closest_marker("cassette_name")
        if marker is None:
            return vcr_cassette_name
        return str(marker.args[0])
