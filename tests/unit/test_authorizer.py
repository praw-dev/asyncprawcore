"""Test for asyncprawcore.auth.Authorizer classes."""

import pytest

import asyncprawcore

from . import UnitTest


class InvalidAuthenticator(asyncprawcore.auth.BaseAuthenticator):
    _auth = None


class TestAuthorizer(UnitTest):
    async def test_authorize__fail_without_redirect_uri(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(authenticator=trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.authorize("dummy code")
        assert not authorizer.is_valid()

    def test_initialize(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(authenticator=trusted_authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert authorizer.refresh_token is None
        assert not authorizer.is_valid()

    def test_initialize__with_refresh_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(
            authenticator=trusted_authenticator, refresh_token=pytest.placeholders.refresh_token
        )
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert pytest.placeholders.refresh_token == authorizer.refresh_token
        assert not authorizer.is_valid()

    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(client_id=None, requestor=None)
        authorizer = asyncprawcore.Authorizer(authenticator=authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert authorizer.refresh_token is None
        assert not authorizer.is_valid()

    async def test_refresh__without_refresh_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(authenticator=trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.refresh()
        assert not authorizer.is_valid()

    async def test_revoke__without_access_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(
            authenticator=trusted_authenticator, refresh_token=pytest.placeholders.refresh_token
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke(only_access=True)

    async def test_revoke__without_any_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(authenticator=trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke()


class TestDeviceIDAuthorizer(UnitTest):
    def test_initialize(self, untrusted_authenticator):
        authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator=untrusted_authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

    def test_initialize__with_invalid_authenticator(self):
        authenticator = asyncprawcore.Authorizer(
            authenticator=InvalidAuthenticator(client_id=None, redirect_uri=None, requestor=None)
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.DeviceIDAuthorizer(authenticator=authenticator)


class TestImplicitAuthorizer(UnitTest):
    def test_initialize(self, untrusted_authenticator):
        authorizer = asyncprawcore.ImplicitAuthorizer(
            access_token="fake token", authenticator=untrusted_authenticator, expires_in=1, scope="modposts read"
        )
        assert authorizer.access_token == "fake token"
        assert authorizer.scopes == {"modposts", "read"}
        assert authorizer.is_valid()

    def test_initialize__with_trusted_authenticator(self, trusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ImplicitAuthorizer(
                access_token=None, authenticator=trusted_authenticator, expires_in=None, scope=None
            )


class TestReadOnlyAuthorizer(UnitTest):
    def test_initialize__with_untrusted_authenticator(self, untrusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ReadOnlyAuthorizer(authenticator=untrusted_authenticator)


class TestScriptAuthorizer(UnitTest):
    def test_initialize__with_untrusted_authenticator(self, untrusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ScriptAuthorizer(authenticator=untrusted_authenticator, password=None, username=None)
