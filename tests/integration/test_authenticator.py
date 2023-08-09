"""Test for subclasses of asyncprawcore.auth.BaseAuthenticator class."""
import pytest

import asyncprawcore

from . import IntegrationTest


class TestTrustedAuthenticator(IntegrationTest):
    async def test_revoke_token(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        await authenticator.revoke_token("dummy token")

    async def test_revoke_token__with_access_token_hint(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        await authenticator.revoke_token("dummy token", "access_token")

    async def test_revoke_token__with_refresh_token_hint(self, requestor):
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        await authenticator.revoke_token("dummy token", "refresh_token")


class TestUntrustedAuthenticator(IntegrationTest):
    async def test_revoke_token(self, requestor):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            requestor, pytest.placeholders.client_id
        )
        await authenticator.revoke_token("dummy token")
