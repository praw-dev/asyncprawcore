"""Test for asyncprawcore.auth.Authorizer classes."""
import asyncprawcore
import unittest
from .conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    PERMANENT_GRANT_CODE,
    REDIRECT_URI,
    REFRESH_TOKEN,
    REQUESTOR,
    TEMPORARY_GRANT_CODE,
    USERNAME,
    VCR,
)


class AuthorizerTestBase(unittest.TestCase):
    def setUp(self):
        self.authentication = asyncprawcore.TrustedAuthenticator(
            REQUESTOR, CLIENT_ID, CLIENT_SECRET
        )


class AuthorizerTest(AuthorizerTestBase):
    def test_authorize__with_permanent_grant(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette(
            "Authorizer_authorize__with_permanent_grant"
        ):
            authorizer.authorize(PERMANENT_GRANT_CODE)

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsNotNone(authorizer.refresh_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    def test_authorize__with_temporary_grant(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette(
            "Authorizer_authorize__with_temporary_grant"
        ):
            authorizer.authorize(TEMPORARY_GRANT_CODE)

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    def test_authorize__with_invalid_code(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette(
            "Authorizer_authorize__with_invalid_code"
        ):
            self.assertRaises(
                asyncprawcore.OAuthException,
                authorizer.authorize,
                "invalid code",
            )
        self.assertFalse(authorizer.is_valid())

    def test_authorize__fail_without_redirect_uri(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        self.assertRaises(
            asyncprawcore.InvalidInvocation, authorizer.authorize, "dummy code"
        )
        self.assertFalse(authorizer.is_valid())

    def test_initialize(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertIsNone(authorizer.refresh_token)
        self.assertFalse(authorizer.is_valid())

    def test_initialize__with_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
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

    def test_refresh(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
        with VCR.use_cassette("Authorizer_refresh"):
            authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertIsInstance(authorizer.scopes, set)
        self.assertTrue(len(authorizer.scopes) > 0)
        self.assertTrue(authorizer.is_valid())

    def test_refresh__with_invalid_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, "INVALID_TOKEN"
        )
        with VCR.use_cassette(
            "Authorizer_refresh__with_invalid_token"
        ):
            self.assertRaises(
                asyncprawcore.ResponseException, authorizer.refresh
            )
            self.assertFalse(authorizer.is_valid())

    def test_refresh__without_refresh_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        self.assertRaises(asyncprawcore.InvalidInvocation, authorizer.refresh)
        self.assertFalse(authorizer.is_valid())

    def test_revoke__access_token_with_refresh_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
        with VCR.use_cassette(
            "Authorizer_revoke__access_token_with_refresh_set"
        ):
            authorizer.refresh()
            authorizer.revoke(only_access=True)

            self.assertIsNone(authorizer.access_token)
            self.assertIsNotNone(authorizer.refresh_token)
            self.assertIsNone(authorizer.scopes)
            self.assertFalse(authorizer.is_valid())

            authorizer.refresh()

        self.assertTrue(authorizer.is_valid())

    def test_revoke__access_token_without_refresh_set(self):
        self.authentication.redirect_uri = REDIRECT_URI
        authorizer = asyncprawcore.Authorizer(self.authentication)
        with VCR.use_cassette(
            "Authorizer_revoke__access_token_without_refresh_set"
        ):
            authorizer.authorize(TEMPORARY_GRANT_CODE)
            authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    def test_revoke__refresh_token_with_access_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
        with VCR.use_cassette(
            "Authorizer_revoke__refresh_token_with_access_set"
        ):
            authorizer.refresh()
            authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    def test_revoke__refresh_token_without_access_set(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
        with VCR.use_cassette(
            "Authorizer_revoke__refresh_token_without_access_set"
        ):
            authorizer.revoke()

        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.refresh_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    def test_revoke__without_access_token(self):
        authorizer = asyncprawcore.Authorizer(
            self.authentication, REFRESH_TOKEN
        )
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            authorizer.revoke,
            only_access=True,
        )

    def test_revoke__without_any_token(self):
        authorizer = asyncprawcore.Authorizer(self.authentication)
        self.assertRaises(asyncprawcore.InvalidInvocation, authorizer.revoke)


class DeviceIDAuthorizerTest(AuthorizerTestBase):
    def setUp(self):
        self.authentication = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )

    def test_initialize(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

    def test_initialize__with_trusted_authenticator(self):
        authenticator = asyncprawcore.TrustedAuthenticator(None, None, None)
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.DeviceIDAuthorizer,
            authenticator,
        )

    def test_refresh(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(self.authentication)
        with VCR.use_cassette("DeviceIDAuthorizer_refresh"):
            authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual(set(["*"]), authorizer.scopes)
        self.assertTrue(authorizer.is_valid())

    def test_refresh__with_short_device_id(self):
        authorizer = asyncprawcore.DeviceIDAuthorizer(
            self.authentication, "a" * 19
        )
        with VCR.use_cassette(
            "DeviceIDAuthorizer_refresh__with_short_device_id"
        ):
            self.assertRaises(asyncprawcore.OAuthException, authorizer.refresh)


class ImplicitAuthorizerTest(AuthorizerTestBase):
    def test_initialize(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
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
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.ReadOnlyAuthorizer,
            authenticator,
        )

    def test_refresh(self):
        authorizer = asyncprawcore.ReadOnlyAuthorizer(self.authentication)
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

        with VCR.use_cassette("ReadOnlyAuthorizer_refresh"):
            authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual(set(["*"]), authorizer.scopes)
        self.assertTrue(authorizer.is_valid())


class ScriptAuthorizerTest(AuthorizerTestBase):
    def test_initialize__with_untrusted_authenticator(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            REQUESTOR, CLIENT_ID
        )
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            asyncprawcore.ScriptAuthorizer,
            authenticator,
            None,
            None,
        )

    def test_refresh(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication, USERNAME, PASSWORD
        )
        self.assertIsNone(authorizer.access_token)
        self.assertIsNone(authorizer.scopes)
        self.assertFalse(authorizer.is_valid())

        with VCR.use_cassette("ScriptAuthorizer_refresh"):
            authorizer.refresh()

        self.assertIsNotNone(authorizer.access_token)
        self.assertEqual(set(["*"]), authorizer.scopes)
        self.assertTrue(authorizer.is_valid())

    def test_refresh__with_invalid_username_or_password(self):
        authorizer = asyncprawcore.ScriptAuthorizer(
            self.authentication, USERNAME, "invalidpassword"
        )
        with VCR.use_cassette(
            "ScriptAuthorizer_refresh__with_invalid_username_or_password"
        ):
            self.assertRaises(asyncprawcore.OAuthException, authorizer.refresh)
            self.assertFalse(authorizer.is_valid())
