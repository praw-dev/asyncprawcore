"""asyncprawcore Unit test suite."""
import asynctest
from mock import Mock

import asyncprawcore


class UnitTest(asynctest.TestCase):
    """Base class for asyncprawcore unit tests."""
    async def setUp(self) -> None:
        self.requestor = asyncprawcore.requestor.Requestor(
            "asyncprawcore:test (by /u/Lil_SpazJoekp)"
        )

    async def tearDown(self) -> None:
        if hasattr(self, "requestor"):
            if isinstance(self.requestor, asyncprawcore.requestor.Requestor):
                if not isinstance(self.requestor._http, Mock):
                    await self.requestor.close()
