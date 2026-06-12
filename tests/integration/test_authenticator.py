"""Test for subclasses of asyncprawcore.auth.BaseAuthenticator class."""

import pytest

import asyncprawcore

from . import IntegrationTest


class TestTrustedAuthenticator(IntegrationTest):
    async def test_revoke_token(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            client_id=pytest.placeholders.client_id,
            client_secret=pytest.placeholders.client_secret,
            requestor=requestor,
        )
        await authenticator.revoke_token("dummy token")

    async def test_revoke_token__with_access_token_hint(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            client_id=pytest.placeholders.client_id,
            client_secret=pytest.placeholders.client_secret,
            requestor=requestor,
        )
        await authenticator.revoke_token("dummy token", token_type="access_token")

    async def test_revoke_token__with_refresh_token_hint(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            client_id=pytest.placeholders.client_id,
            client_secret=pytest.placeholders.client_secret,
            requestor=requestor,
        )
        await authenticator.revoke_token("dummy token", token_type="refresh_token")


class TestUntrustedAuthenticator(IntegrationTest):
    async def test_revoke_token(self, requestor):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            client_id=pytest.placeholders.client_id, requestor=requestor
        )
        await authenticator.revoke_token("dummy token")
