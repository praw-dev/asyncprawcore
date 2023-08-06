"""Test for asyncprawcore.auth.Authorizer classes."""
import pytest

import asyncprawcore

from ..conftest import two_factor_callback  # noqa F401
from . import IntegrationTest


class AuthorizerBase(IntegrationTest):
    async def setUp(self):
        await super().setUp()
        self.authentication = asyncprawcore.TrustedAuthenticator(
            self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )

    async def tearDown(self) -> None:
        await self.requestor.close()


class TestAuthorizer(AuthorizerBase):
    async def test_authorize__with_invalid_code(self):
        self.authentication.redirect_uri = pytest.placeholders.redirect_uri
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.use_cassette():
            with pytest.raises(asyncprawcore.OAuthException):
                await authorizer.authorize("invalid code")
        assert not authorizer.is_valid()

    async def test_authorize__with_permanent_grant(self):
        self.authentication.redirect_uri = pytest.placeholders.redirect_uri
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.use_cassette():
            await authorizer.authorize(pytest.placeholders.permanent_grant_code)

        assert authorizer.access_token is not None
        assert authorizer.refresh_token is not None
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_authorize__with_temporary_grant(self):
        self.authentication.redirect_uri = pytest.placeholders.redirect_uri
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.use_cassette():
            await authorizer.authorize(pytest.placeholders.temporary_grant_code)

        assert authorizer.access_token is not None
        assert authorizer.refresh_token is None
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh__post_refresh_callback(self):
        def callback(authorizer):
            assert authorizer.refresh_token != pytest.placeholders.refresh_token
            authorizer.refresh_token = "manually_updated"

        authorizer = asyncprawcore.Authorizer(
            self.authentication,
            post_refresh_callback=callback,
            refresh_token=pytest.placeholders.refresh_token,
        )
        with self.use_cassette("TestAuthorizer.test_refresh"):
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.refresh_token == "manually_updated"
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh__post_refresh_callback__async(self):
        async def callback(authorizer):
            assert authorizer.refresh_token != pytest.placeholders.refresh_token
            authorizer.refresh_token = "manually_updated"

        authorizer = asyncprawcore.Authorizer(
            self.authentication,
            post_refresh_callback=callback,
            refresh_token=pytest.placeholders.refresh_token,
        )
        with self.use_cassette("TestAuthorizer.test_refresh"):
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.refresh_token == "manually_updated"
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh__pre_refresh_callback(self):
        def callback(authorizer):
            assert authorizer.refresh_token is None
            authorizer.refresh_token = pytest.placeholders.refresh_token

        authorizer = asyncprawcore.Authorizer(
            self.authentication, pre_refresh_callback=callback
        )
        with self.use_cassette("TestAuthorizer.test_refresh"):
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh__pre_refresh_callback__async(self):
        async def callback(authorizer):
            assert authorizer.refresh_token is None
            authorizer.refresh_token = pytest.placeholders.refresh_token

        authorizer = asyncprawcore.Authorizer(
            self.authentication, pre_refresh_callback=callback
        )
        with self.use_cassette("TestAuthorizer.test_refresh"):
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert isinstance(authorizer.scopes, set)
        assert len(authorizer.scopes) > 0
        assert authorizer.is_valid()

    async def test_refresh__with_invalid_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token="INVALID_TOKEN"
        )
        with self.use_cassette():
            with pytest.raises(asyncprawcore.ResponseException):
                await authorizer.refresh()
            assert not authorizer.is_valid()

    async def test_revoke__access_token_with_refresh_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
        with self.use_cassette():
            await authorizer.refresh()
            await authorizer.revoke(only_access=True)

            assert authorizer.access_token is None
            assert authorizer.refresh_token is not None
            assert authorizer.scopes is None
            assert not authorizer.is_valid()

            await authorizer.refresh()

        assert authorizer.is_valid()

    async def test_revoke__access_token_without_refresh_set(self):
        self.authentication.redirect_uri = pytest.placeholders.redirect_uri
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.use_cassette():
            await authorizer.authorize(pytest.placeholders.temporary_grant_code)
            await authorizer.revoke()

        assert authorizer.access_token is None
        assert authorizer.refresh_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

    async def test_revoke__refresh_token_with_access_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
        with self.use_cassette():
            await authorizer.refresh()
            await authorizer.revoke()

        assert authorizer.access_token is None
        assert authorizer.refresh_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

    async def test_revoke__refresh_token_without_access_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, refresh_token=pytest.placeholders.refresh_token
        )
        with self.use_cassette():
            await authorizer.revoke()

        assert authorizer.access_token is None
        assert authorizer.refresh_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()


class TestDeviceIDAuthorizer(AuthorizerBase):
    async def setUp(self):
        await super().setUp()
        self.authentication = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )

    async def test_refresh(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == {"*"}
        assert authorizer.is_valid()

    async def test_refresh__with_scopes_and_trusted_authenticator(self):
        scope_list = {"adsedit", "adsread", "creddits", "history"}
        authorizer = asyncprawcore.DeviceIDAuthorizer(
            asyncprawcore.TrustedAuthenticator(
                self.requestor,
                pytest.placeholders.client_id,
                pytest.placeholders.client_secret,
            ),
            scopes=scope_list,
        )
        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == scope_list
        assert authorizer.is_valid()

    async def test_refresh__with_short_device_id(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication, "a" * 19)
        with self.use_cassette():
            with pytest.raises(asyncprawcore.OAuthException):
                await authorizer.refresh()


class TestReadOnlyAuthorizer(AuthorizerBase):
    async def test_refresh(self):
        authorizer = asyncprawcore.ReadOnlyAuthorizer(self.authentication)
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == {"*"}
        assert authorizer.is_valid()

    async def test_refresh__with_scopes(self):
        scope_list = {"adsedit", "adsread", "creddits", "history"}
        authorizer = asyncprawcore.ReadOnlyAuthorizer(
            self.authentication, scopes=scope_list
        )
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == scope_list
        assert authorizer.is_valid()


class TestScriptAuthorizer(AuthorizerBase):
    async def test_refresh(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication,
            pytest.placeholders.username,
            pytest.placeholders.password,
        )
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == {"*"}
        assert authorizer.is_valid()

    async def test_refresh__with_invalid_otp(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication,
            pytest.placeholders.username,
            pytest.placeholders.password,
            lambda: "fake",
        )

        with self.use_cassette():
            with pytest.raises(asyncprawcore.OAuthException):
                await authorizer.refresh()
        assert not authorizer.is_valid()

    async def test_refresh__with_invalid_username_or_password(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication, pytest.placeholders.username, "invalidpassword"
        )
        with self.use_cassette():
            with pytest.raises(asyncprawcore.OAuthException):
                await authorizer.refresh()
        assert not authorizer.is_valid()

    async def test_refresh__with_scopes(self):
        scope_list = {"adsedit", "adsread", "creddits", "history"}
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication,
            pytest.placeholders.username,
            pytest.placeholders.password,
            scopes=scope_list,
        )
        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == scope_list
        assert authorizer.is_valid()

    async def test_refresh__with_valid_otp(self):
        def otp_function():
            return "000000"

        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication,
            pytest.placeholders.username,
            pytest.placeholders.password,
            otp_function,
        )
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

        with self.use_cassette():
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == {"*"}
        assert authorizer.is_valid()

    async def test_refresh_with__valid_otp_async(self):
        async def otp_function():
            return "000000"

        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication,
            pytest.placeholders.username,
            pytest.placeholders.password,
            otp_function,
        )
        assert authorizer.access_token is None
        assert authorizer.scopes is None
        assert not authorizer.is_valid()

        with self.use_cassette("TestScriptAuthorizer.test_refresh__with_valid_otp"):
            await authorizer.refresh()

        assert authorizer.access_token is not None
        assert authorizer.scopes == {"*"}
        assert authorizer.is_valid()
