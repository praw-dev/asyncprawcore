"""Test for asyncprawcore.auth.Authorizer classes."""

import pytest

import asyncprawcore

from . import UnitTest


class InvalidAuthenticator(asyncprawcore.auth.BaseAuthenticator):
    _auth = None


class TestAuthorizer(UnitTest):
    async def test_authorize__fail_without_redirect_uri(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.authorize("dummy code")
        assert not authorizer.is_valid()

    def test_initialize(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert authorizer.refresh_token is None
        assert not authorizer.is_valid()

    def test_initialize__with_refresh_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator, refresh_token=pytest.placeholders.refresh_token)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert pytest.placeholders.refresh_token == authorizer.refresh_token
        assert not authorizer.is_valid()

    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(None, None)
        authorizer = asyncprawcore.Authorizer(authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert authorizer.refresh_token is None
        assert not authorizer.is_valid()

    async def test_refresh__without_refresh_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.refresh()
        assert not authorizer.is_valid()

    async def test_revoke__without_access_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator, refresh_token=pytest.placeholders.refresh_token)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke(only_access=True)

    async def test_revoke__without_any_token(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(trusted_authenticator)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke()


class TestDeviceIDAuthorizer(UnitTest):
    def test_initialize(self, untrusted_authenticator):
        authorizer = asyncprawcore.DeviceIDAuthorizer(untrusted_authenticator)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

    def test_initialize__with_invalid_authenticator(self):
        authenticator = asyncprawcore.Authorizer(InvalidAuthenticator(None, None, None))
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.DeviceIDAuthorizer(authenticator)


class TestImplicitAuthorizer(UnitTest):
    def test_initialize(self, untrusted_authenticator):
        authorizer = asyncprawcore.ImplicitAuthorizer(untrusted_authenticator, "fake token", 1, "modposts read")
        assert authorizer.access_token == "fake token"
        assert authorizer.scopes == {"modposts", "read"}
        assert authorizer.is_valid()

    def test_initialize__with_trusted_authenticator(self, trusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ImplicitAuthorizer(trusted_authenticator, None, None, None)


class TestReadOnlyAuthorizer(UnitTest):
    def test_initialize__with_untrusted_authenticator(self, untrusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ReadOnlyAuthorizer(untrusted_authenticator)


class TestScriptAuthorizer(UnitTest):
    def test_initialize__with_untrusted_authenticator(self, untrusted_authenticator):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ScriptAuthorizer(untrusted_authenticator, None, None)
