"""Test for asyncprawcore.Sessions module."""
import logging
from json import dumps

import aiofiles as aiofiles
import pytest
from mock import patch
from testfixtures import LogCapture

import asyncprawcore

from ..conftest import two_factor_callback
from . import IntegrationTest


class InvalidAuthorizer(asyncprawcore.Authorizer):
    def __init__(self, requestor):
        super(InvalidAuthorizer, self).__init__(
            asyncprawcore.TrustedAuthenticator(
                requestor,
                pytest.placeholders.client_id,
                pytest.placeholders.client_secret,
            )
        )

    def is_valid(self):
        return False


class TestSession(IntegrationTest):
    async def client_authorizer(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        authorizer = asyncprawcore.Authorizer(
            authenticator, refresh_token=pytest.placeholders.refresh_token
        )
        await authorizer.refresh()
        return authorizer

    async def readonly_authorizer(self, refresh=True, requestor=None):
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor or self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        if refresh:
            await authorizer.refresh()
        return authorizer

    async def script_authorizer(self):
        authenticator = asyncprawcore.TrustedAuthenticator(
            self.requestor,
            pytest.placeholders.client_id,
            pytest.placeholders.client_secret,
        )
        authorizer = asyncprawcore.ScriptAuthorizer(
            authenticator,
            pytest.placeholders.username,
            pytest.placeholders.password,
            two_factor_callback,
        )
        await authorizer.refresh()
        return authorizer

    async def test_request__accepted(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with LogCapture(level=logging.DEBUG) as log_capture:
                await session.request("POST", "api/read_all_messages")
            log_capture.check_present(
                ("asyncprawcore", "DEBUG", "Response: 202 (2 bytes)")
            )

    async def test_request__get(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            params = {"limit": 100, "bool_param": True}
            response = await session.request("GET", "/", params=params)
        assert isinstance(response, dict)
        assert len(params) == 2
        assert response["kind"] == "Listing"

    async def test_request__patch(self):
        with self.use_cassette(
            match_requests_on=["method", "uri", "body"],
        ):
            session = asyncprawcore.Session(await self.script_authorizer())
            json = {"lang": "ja", "num_comments": 123}
            response = await session.request("PATCH", "/api/v1/me/prefs", json=json)
            assert response["lang"] == "ja"
            assert response["num_comments"] == 123

    async def test_request__post(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            data = {
                "kind": "self",
                "sr": "asyncpraw",
                "text": "Test!",
                "title": "A Test from asyncprawcore.",
            }
            key_count = len(data)
            response = await session.request("POST", "/api/submit", data=data)
            assert "a_test_from_asyncprawcore" in response["json"]["data"]["url"]
            assert key_count == len(data)  # Ensure data is untouched

    async def test_request__post__with_aiofiles(self):
        with self.use_cassette(
            "TestSession.test_request__post__with_files",
            match_requests_on=["uri", "method"],
        ):
            session = asyncprawcore.Session(await self.script_authorizer())
            data = {"upload_type": "header"}
            async with aiofiles.open(
                "tests/integration/files/white-square.png", "rb"
            ) as fp:
                files = {"file": fp}
                response = await session.request(
                    "POST",
                    "/r/asyncpraw/api/upload_sr_img",
                    data=data,
                    files=files,
                )
            assert "img_src" in response

    async def test_request__post__with_files(self):
        with self.use_cassette(
            "TestSession.test_request__post__with_files",
            match_requests_on=["uri", "method"],
        ):
            session = asyncprawcore.Session(await self.script_authorizer())
            data = {"upload_type": "header"}
            with open("tests/integration/files/white-square.png", "rb") as fp:
                files = {"file": fp}
                response = await session.request(
                    "POST",
                    "/r/asyncpraw/api/upload_sr_img",
                    data=data,
                    files=files,
                )
            assert "img_src" in response

    async def test_request__raw_json(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            response = await session.request(
                "GET",
                "/r/reddit_api_test/comments/45xjdr/want_raw_json_test/",
            )
        assert (
            "WANT_RAW_JSON test: < > &"
            == response[0]["data"]["children"][0]["data"]["title"]
        )

    @patch("asyncio.sleep", return_value=None)
    async def test_request__bad_gateway(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
            assert exception_info.value.response.status == 502

    async def test_request__bad_json(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with pytest.raises(asyncprawcore.BadJSON) as exception_info:
                await session.request("GET", "/")
            assert exception_info.value.response.content_length == 17512

    async def test_request__bad_request(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with pytest.raises(asyncprawcore.BadRequest) as exception_info:
                await session.request(
                    "PUT",
                    "/api/v1/me/friends/spez",
                    data='{"note": "asyncprawcore"}',
                )
            assert "reason" in (await exception_info.value.response.json())

    @patch("asyncio.sleep", return_value=None)
    async def test_request__cloudflare_connection_timed_out(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
                await session.request("GET", "/")
                await session.request("GET", "/")
            assert exception_info.value.response.status == 522

    @patch("asyncio.sleep", return_value=None)
    async def test_request__cloudflare_unknown_error(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
                await session.request("GET", "/")
                await session.request("GET", "/")
            assert exception_info.value.response.status == 520

    async def test_request__conflict(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with pytest.raises(asyncprawcore.Conflict) as exception_info:
                await session.request(
                    "POST",
                    "/api/multi/copy/",
                    data={
                        "display_name": "sfwpornnetwork",
                        "from": "/user/kjoneslol/m/sfwpornnetwork",
                        "to": f"user/{pytest.placeholders.username}/m/sfwpornnetwork/",
                    },
                )
            assert exception_info.value.response.status == 409

    async def test_request__created(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            response = await session.request(
                "PUT", "/api/v1/me/friends/spez", data="{}"
            )
            assert "name" in response

    async def test_request__forbidden(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with pytest.raises(asyncprawcore.Forbidden):
                await session.request(
                    "GET",
                    "/user/spez/gilded/given",
                )

    @patch("asyncio.sleep", return_value=None)
    async def test_request__gateway_timeout(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
            assert exception_info.value.response.status == 504

    @patch("asyncio.sleep", return_value=None)
    async def test_request__internal_server_error(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
            assert exception_info.value.response.status == 500

    async def test_request__no_content(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            response = await session.request("DELETE", "/api/v1/me/friends/spez")
            assert response is None

    async def test_request__not_found(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            with pytest.raises(asyncprawcore.NotFound):
                await session.request(
                    "GET",
                    "/r/cricket/wiki/invalid",
                )

    async def test_request__okay_with_0_byte_content(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.script_authorizer())
            data = {"model": dumps({"name": "redditdev"})}
            path = f"/api/multi/user/{pytest.placeholders.username}/m/test"
            response = await session.request("DELETE", path, data=data)
            assert response == ""

    async def test_request__redirect(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.Redirect) as exception_info:
                await session.request("GET", "/r/random")
            assert exception_info.value.path.startswith("/r/")

    async def test_request__redirect_301(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.Redirect) as exception_info:
                await session.request("GET", "t/bird")
            assert exception_info.value.path == "/r/t:bird/"

    @patch("asyncio.sleep", return_value=None)
    async def test_request__service_unavailable(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            with pytest.raises(asyncprawcore.ServerError) as exception_info:
                await session.request("GET", "/")
                await session.request("GET", "/")
                await session.request("GET", "/")
            assert exception_info.value.response.status == 503

    async def test_request__too_large(self):
        with self.use_cassette(match_requests_on=["uri", "method"]):
            session = asyncprawcore.Session(await self.script_authorizer())
            data = {"upload_type": "header"}
            with pytest.raises(asyncprawcore.TooLarge) as exception_info:
                await session.request(
                    "POST",
                    "/r/asyncpraw/api/upload_sr_img",
                    data=data,
                    files={
                        "file": open("./tests/integration/files/too_large.jpg", "rb")
                    },
                )
            assert exception_info.value.response.status == 413

    async def test_request__too__many_requests__with_retry_headers(self):
        with self.use_cassette():
            session = asyncprawcore.Session(
                await self.readonly_authorizer(requestor=self.requestor)
            )
            session._requestor._http.headers.update(
                {"User-Agent": "python-requests/2.25.1"}
            )
            with pytest.raises(asyncprawcore.TooManyRequests) as exception_info:
                await session.request("GET", "/api/v1/me")
            assert exception_info.value.response.status == 429
            assert exception_info.value.response.headers.get("retry-after")
            assert exception_info.value.response.reason == "Too Many Requests"
            assert str(exception_info.value).startswith(
                "received 429 HTTP response. Please wait at least"
            )
            assert (await exception_info.value.message()).startswith(
                "\n<!doctype html>"
            )

    async def test_request__too__many_requests__without_retry_headers(self):
        requestor = asyncprawcore.Requestor("python-requests/2.25.1")

        with self.use_cassette():
            with pytest.raises(
                asyncprawcore.exceptions.ResponseException
            ) as exception_info:
                asyncprawcore.Session(
                    await self.readonly_authorizer(requestor=requestor)
                )
            assert exception_info.value.response.status == 429
            assert not exception_info.value.response.headers.get("retry-after")
            assert exception_info.value.response.reason == "Too Many Requests"
            assert await exception_info.value.response.json() == {
                "message": "Too Many Requests",
                "error": 429,
            }

    async def test_request__unavailable_for_legal_reasons(self):
        with self.use_cassette():
            authenticator = asyncprawcore.UntrustedAuthenticator(
                self.requestor, pytest.placeholders.client_id
            )
            authorizer = asyncprawcore.ImplicitAuthorizer(authenticator, None, 0, "")
            session = asyncprawcore.Session(authorizer)
            exception_class = asyncprawcore.UnavailableForLegalReasons
            with pytest.raises(exception_class) as exception_info:
                await session.request("GET", "/")
            assert exception_info.value.response.status == 451

    async def test_request__unsupported_media_type(self):
        with self.use_cassette(
            match_requests_on=["uri", "method"],
        ):
            session = asyncprawcore.Session(await self.script_authorizer())
            exception_class = asyncprawcore.SpecialError
            data = {
                "content": "type: submission\naction: upvote",
                "page": "config/automoderator",
            }
            with pytest.raises(exception_class) as exception_info:
                await session.request("POST", "r/asyncpraw/api/wiki/edit/", data=data)
            assert exception_info.value.response.status == 415

    async def test_request__uri_too_long(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            path_start = "/api/morechildren?link_id=t3_n7r3uz&children="
            with open("tests/integration/files/comment_ids.txt") as fp:
                ids = fp.read()
            with pytest.raises(asyncprawcore.URITooLong) as exception_info:
                await session.request("GET", (path_start + ids)[:9996])
            assert exception_info.value.response.status == 414

    async def test_request__with_insufficient_scope(self):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.client_authorizer())
            with pytest.raises(asyncprawcore.InsufficientScope):
                await session.request("GET", "/api/v1/me")

    async def test_request__with_invalid_access_token(self):
        authenticator = asyncprawcore.UntrustedAuthenticator(
            self.requestor, pytest.placeholders.client_id
        )
        authorizer = asyncprawcore.ImplicitAuthorizer(authenticator, None, 0, "")
        session = asyncprawcore.Session(authorizer)

        with self.use_cassette():
            session._authorizer.access_token = "invalid"
            with pytest.raises(asyncprawcore.InvalidToken):
                await session.request("get", "/")

    @patch("asyncio.sleep", return_value=None)
    async def test_request__with_invalid_access_token__retry(self, _):
        with self.use_cassette():
            session = asyncprawcore.Session(await self.readonly_authorizer())
            session._authorizer.access_token += "invalid"
            response = await session.request("GET", "/")
        assert isinstance(response, dict)
