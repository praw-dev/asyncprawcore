"""Test for subclasses of asyncprawcore.auth.BaseAuthenticator class."""
import pytest

import asyncprawcore
from . import IntegrationTest


class TestTrustedAuthenticator(IntegrationTest):
    async def setUp(self):
        await super().setUp()
        self.authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )

    async def test_revoke_token(self):
        with self.use_cassette():
            await self.authenticator.revoke_token("dummy token")

    async def test_revoke_token__with_access_token_hint(self):
        with self.use_cassette():
            await self.authenticator.revoke_token("dummy token", "access_token")

    async def test_revoke_token__with_refresh_token_hint(self):
        with self.use_cassette():
            await self.authenticator.revoke_token("dummy token", "refresh_token")


class TestUntrustedAuthenticator(IntegrationTest):
    async def test_revoke_token(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        with self.use_cassette():
            await authenticator.revoke_token("dummy token")
