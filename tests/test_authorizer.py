"""Test for asyncprawcore.auth.Authorizer classes."""
import asyncprawcore
import asynctest
from asyncprawcore.requestor import Requestor
from .conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    PERMANENT_GRANT_CODE,
    REDIRECT_URI,
    REFRESH_TOKEN,
    TEMPORARY_GRANT_CODE,
    USERNAME,
    VCR,
)


class AuthorizerTestBase(asynctest.TestCase):
    async def setUp(self):
        self.requestor = Requestor("asyncprawcore:test (by /u/bboe)")
        self.authentication = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET
        )

    async def tearDown(self) -> None:
        await self.requestor.close()


class AuthorizerTest(AuthorizerTestBase):
    async def test_authorize__with_permanent_grant(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette("Authorizer_authorize__with_permanent_grant"):
            await authorizer.authorize(PERMANENT_GRANT_CODE)

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsNotNone(authorizer.refresh_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    async def test_authorize__with_temporary_grant(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette("Authorizer_authorize__with_temporary_grant"):
            await authorizer.authorize(TEMPORARY_GRANT_CODE)

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    async def test_authorize__with_invalid_code(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette("Authorizer_authorize__with_invalid_code"):
            with self.assertRaises(asyncprawcore.OAuthException):
                await authorizer.authorize("invalid code")
        self.assertFalse(authorizer.is_valid())

    async def test_authorize__fail_without_redirect_uri(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            await authorizer.authorize("dummy code")
        self.assertFalse(authorizer.is_valid())

    def test_initialize(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertIsNone(authorizer.refresh_token)
        self.assertFalse(authorizer.is_valid())

    def test_initialize__with_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertEqual(REFRESH_TOKEN, authorizer.refresh_token)
        self.assertFalse(authorizer.is_valid())

    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(None, None)
        authorizer = asyncprawcore.Authorizer(authenticator)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertIsNone(authorizer.refresh_token)
        self.assertFalse(authorizer.is_valid())

    async def test_refresh(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        with VCR.use_cassette("Authorizer_refresh"):
            await authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    async def test_refresh__with_invalid_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, "INVALID_TOKEN")
        with VCR.use_cassette("Authorizer_refresh__with_invalid_token"):
            with self.assertRaises(asyncprawcore.ResponseException):
                await authorizer.refresh()
            self.assertFalse(authorizer.is_valid())

    async def test_refresh__without_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            await authorizer.refresh()
        self.assertFalse(authorizer.is_valid())

    async def test_revoke__access_token_with_refresh_set(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        with VCR.use_cassette("Authorizer_revoke__access_token_with_refresh_set"):
            await authorizer.refresh()
            await authorizer.revoke(only_access=True)

            self.assertIsNone(authorizer.access_token)
            self.assertIsNotNone(authorizer.refresh_token)
            self.assertIsNone(authorizer.scopes)
            self.assertFalse(authorizer.is_valid())

            await authorizer.refresh()

        self.assertTrue(authorizer.is_valid())

    async def test_revoke__access_token_without_refresh_set(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette("Authorizer_revoke__access_token_without_refresh_set"):
            await authorizer.authorize(TEMPORARY_GRANT_CODE)
            await authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    async def test_revoke__refresh_token_with_access_set(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        with VCR.use_cassette("Authorizer_revoke__refresh_token_with_access_set"):
            await authorizer.refresh()
            await authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    async def test_revoke__refresh_token_without_access_set(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        with VCR.use_cassette("Authorizer_revoke__refresh_token_without_access_set"):
            await authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    async def test_revoke__without_access_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication, REFRESH_TOKEN)
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke(only_access=True)

    async def test_revoke__without_any_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            await authorizer.revoke()


class DeviceIDAuthorizerTest(AuthorizerTestBase):
    async def setUp(self):
        self.requestor = Requestor("asyncprawcore:test (by /u/bboe)")

        self.authentication = asyncprawcore.UntrustedAuthenticator(
            self.requestor, CLIENT_ID
        )

    async def test_initialize(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    async def test_initialize__with_trusted_authenticator(self):
        authenticator = asyncprawcore.TrustedAuthenticator(None, None, None)
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            asyncprawcore.DeviceIDAuthorizer(authenticator)

    async def test_refresh(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        with VCR.use_cassette("DeviceIDAuthorizer_refresh"):
            await authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual(set(["*"]), authorizer.scopes)
        self.assertTrue(authorizer.is_valid())

    async def test_refresh__with_short_device_id(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication, "a" * 19)
        with VCR.use_cassette("DeviceIDAuthorizer_refresh__with_short_device_id"):
            with self.assertRaises(asyncprawcore.OAuthException):
                await authorizer.refresh()


class ImplicitAuthorizerTest(AuthorizerTestBase):
    def test_initialize(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        authorizer = asyncprawcore.ImplicitAuthorizer(
            authenticator, "fake token", 1, "modposts read"
        )
        self.assertEqual("fake token", authorizer.access_token)
        self.assertEqual({"modposts", "read"}, authorizer.scopes)
        self.assertTrue(authorizer.is_valid())

    def test_initialize__with_trusted_authenticator(self):
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.ImplicitAuthorizer,
            self.authentication,
            None,
            None,
            None,
        )


class ReadOnlyAuthorizerTest(AuthorizerTestBase):
    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.ReadOnlyAuthorizer,
            authenticator,
        )

    async def test_refresh(self):
        authorizer = asyncprawcore.ReadOnlyAuthorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

        with VCR.use_cassette("ReadOnlyAuthorizer_refresh"):
            await authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual(set(["*"]), authorizer.scopes)
        self.assertTrue(authorizer.is_valid())


class ScriptAuthorizerTest(AuthorizerTestBase):
    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.ScriptAuthorizer,
            authenticator,
            None,
            None,
        )

    async def test_refresh(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication, USERNAME, PASSWORD
        )
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

        with VCR.use_cassette("ScriptAuthorizer_refresh"):
            await authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual({"*"}, authorizer.scopes)
        self.assertTrue(authorizer.is_valid())

    async def test_refresh__with_invalid_username_or_password(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication, USERNAME, "invalidpassword"
        )
        with VCR.use_cassette(
            "ScriptAuthorizer_refresh__with_invalid_username_or_password"
        ):
            with self.assertRaises(asyncprawcore.OAuthException):
                await authorizer.refresh()
            self.assertFalse(authorizer.is_valid())
