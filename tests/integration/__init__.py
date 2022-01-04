"""asyncprawcore Integration test suite."""
import inspect
import logging

import asynctest

from asyncprawcore import Requestor

from tests.conftest import vcr

class IntegrationTest(asynctest.TestCase):
    """Base class for asyncprawcore integration tests."""

    logger = logging.getLogger(__name__)

    async def setUp(self):
        """Setup runs before all test cases."""
        self.requestor = Requestor("asyncprawcore:test (by /u/Lil_SpazJoekp)")
        self.recorder = vcr

    async def teardown(self) -> None:
        await self.requestor.close()

    def use_cassette(self, cassette_name=None, **kwargs):
        """Use a cassette. The cassette name is dynamically generated.

        :param cassette_name: (Deprecated) The name to use for the cassette. All names
            that are not equal to the dynamically generated name will be logged.
        :param kwargs: All keyword arguments for the main function
            (``VCR.use_cassette``).

        """
        dynamic_name = self.get_cassette_name()
        if cassette_name:
            self.logger.debug(
                f"Static cassette name provided by {dynamic_name}. The following name "
                f"was provided: {cassette_name}"
            )
            if cassette_name != dynamic_name:
                self.logger.warning(
                    f"Dynamic cassette name for function {dynamic_name} does not match"
                    f" the provided cassette name: {cassette_name}"
                )
        return self.recorder.use_cassette(cassette_name or dynamic_name, **kwargs)

    def get_cassette_name(self) -> str:
        function_name = inspect.currentframe().f_back.f_back.f_code.co_name
        return f"{type(self).__name__}.{function_name}"
