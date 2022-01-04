"""Test for asyncprawcore.auth.Authorizer classes."""
import pytest

import asyncprawcore

from . import UnitTest


class AuthorizerBase(UnitTest):
    async def setUp(self):
        await super().setUp()
        self.authentication = asyncprawcore.TrustedAuthenticator(
            self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )


class TestAuthorizer(AuthorizerBase):
    async def test_authorize__fail_without_redirect_uri(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.authorize("dummy code")
        assert not authorizer.is_valid()

    def test_initialize(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert authorizer.refresh_token is None
        assert not authorizer.is_valid()

    def test_initialize__with_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
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

    async def test_refresh__without_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.refresh()
        assert not authorizer.is_valid()

    async def test_revoke__without_access_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke(only_access=True)

    async def test_revoke__without_any_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with pytest.raises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke()


class TestDeviceIDAuthorizer(AuthorizerBase):
    async def setUp(self):
        await super().setUp()
        self.authentication = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )

    def test_initialize(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

    def test_initialize__with_base_authenticator(self):
        authenticator = asyncprawcore.Authorizer(
            asyncprawcore.auth.BaseAuthenticator(None, None, None)
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.DeviceIDAuthorizer(
                authenticator,
            )


class TestImplicitAuthorizer(AuthorizerBase):
    def test_initialize(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        authorizer = asyncprawcore.ImplicitAuthorizer(
            authenticator, "fake token", 1, "modposts read"
        )
        assert authorizer.access_token == "fake token"
        assert authorizer.scopes == {"modposts", "read"}
        assert authorizer.is_valid()

    def test_initialize__with_trusted_authenticator(self):
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ImplicitAuthorizer(
                self.authentication,
                None,
                None,
                None,
            )


class TestReadOnlyAuthorizer(AuthorizerBase):
    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ReadOnlyAuthorizer(
                authenticator,
            )


class TestScriptAuthorizer(AuthorizerBase):
    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        with pytest.raises(asyncprawcore.InvalidInvocation):
            asyncprawcore.ScriptAuthorizer(authenticator, None, None)
