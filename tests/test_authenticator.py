"""Test for sublcasses of asyncprawcore.auth.BaseAuthenticator class."""
import asyncprawcore
import asynctest

from .conftest import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, VCR
from asyncprawcore.requestor import Requestor


class TrustedAuthenticatorTest(asynctest.TestCase):
    async def setUp(self) -> None:
        self.requestor = Requestor("asyncprawcore:test (by /u/bboe)")

    async def tearDown(self) -> None:
        await self.requestor.close()

    async def test_authorize_url(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
        )
        url = authenticator.authorize_url("permanent", ["identity", "read"], "a_state")
        self.assertIn(f"client_id={CLIENT_ID}", url)
        self.assertIn("duration=permanent", url)
        self.assertIn("response_type=code", url)
        self.assertIn("scope=identity+read", url)
        self.assertIn("state=a_state", url)

    def test_authorize_url__fail_with_implicit(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
        )
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            authenticator.authorize_url,
            "temporary",
            ["identity", "read"],
            "a_state",
            implicit=True,
        )

    def test_authorize_url__fail_without_redirect_uri(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET
        )
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            authenticator.authorize_url,
            "permanent",
            ["identity"],
            "...",
        )

    async def test_revoke_token(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET
        )
        with VCR.use_cassette("TrustedAuthenticator_revoke_token"):
            await authenticator.revoke_token("dummy token")

    async def test_revoke_token__with_access_token_hint(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET
        )
        with VCR.use_cassette(
            "TrustedAuthenticator_revoke_token__with_access_token_hint"
        ):
            await authenticator.revoke_token("dummy token", "access_token")

    async def test_revoke_token__with_refresh_token_hint(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor, CLIENT_ID, CLIENT_SECRET
        )
        with VCR.use_cassette(
            "TrustedAuthenticator_revoke_token__with_refresh_token_hint"
        ):
            await authenticator.revoke_token("dummy token", "refresh_token")


class UntrustedAuthenticatorTest(asynctest.TestCase):
    async def setUp(self) -> None:
        self.requestor = Requestor("asyncprawcore:test (by /u/bboe)")

    async def tearDown(self) -> None:
        await self.requestor.close()

    async def test_authorize_url__code(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, CLIENT_ID, REDIRECT_URI
        )
        url = authenticator.authorize_url("permanent", ["identity", "read"], "a_state")
        self.assertIn(f"client_id={CLIENT_ID}", url)
        self.assertIn("duration=permanent", url)
        self.assertIn("response_type=code", url)
        self.assertIn("scope=identity+read", url)
        self.assertIn("state=a_state", url)

    async def test_authorize_url__token(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, CLIENT_ID, REDIRECT_URI
        )
        url = authenticator.authorize_url(
            "temporary", ["identity", "read"], "a_state", implicit=True
        )
        self.assertIn(f"client_id={CLIENT_ID}", url)
        self.assertIn("duration=temporary", url)
        self.assertIn("response_type=token", url)
        self.assertIn("scope=identity+read", url)
        self.assertIn("state=a_state", url)

    async def test_authorize_url__fail_with_token_and_permanent(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, CLIENT_ID, REDIRECT_URI
        )
        with self.assertRaises(asyncprawcore.InvalidInvocation):
            authenticator.authorize_url(
                "permanent",
                ["identity", "read"],
                "a_state",
                implicit=True,
            )

    def test_authorize_url__fail_without_redirect_uri(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        self.assertRaises(
            asyncprawcore.InvalidInvocation,
            authenticator.authorize_url,
            "temporary",
            ["identity"],
            "...",
        )

    async def test_revoke_token(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(self.requestor, CLIENT_ID)
        with VCR.use_cassette("UntrustedAuthenticator_revoke_token"):
            await authenticator.revoke_token("dummy token")
