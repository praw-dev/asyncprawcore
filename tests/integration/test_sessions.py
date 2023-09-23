"""Test for asyncprawcore.Sessions module."""
import logging
from json import dumps

import pytest

import asyncprawcore

from ..conftest import two_factor_callback
from . import IntegrationTest


class TestSession(IntegrationTest):
    @pytest.fixture
    async def readonly_authorizer(self, trusted_authenticator):
        authorizer = asyncprawcore.ReadOnlyAuthorizer(trusted_authenticator)
        await authorizer.refresh()
        return authorizer

    @pytest.fixture
    async def script_authorizer(self, trusted_authenticator):
        authorizer = asyncprawcore.ScriptAuthorizer(
            trusted_authenticator,
            pytest.placeholders.username,
            pytest.placeholders.password,
            two_factor_callback,
        )
        await authorizer.refresh()
        yield authorizer

    async def test_request__accepted(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer, caplog
    ):
        caplog.set_level(logging.DEBUG)
        session = asyncprawcore.Session(script_authorizer)
        await session.request("POST", "api/read_all_messages")
        found_message = False
        for package, level, message in caplog.record_tuples:
            if (
                package == "asyncprawcore"
                and level == logging.DEBUG
                and "Response: 202 (2 bytes)" in message
            ):
                found_message = True
        assert found_message, f"'Response: 202 (2 bytes)' in {caplog.record_tuples}"

    async def test_request__bad_gateway(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
        assert exception_info.value.response.status == 502

    async def test_request__bad_json(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        with pytest.raises(asyncprawcore.BadJSON) as exception_info:
            await session.request("GET", "/")
        assert exception_info.value.response.content_length == 17512

    async def test_request__bad_request(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        with pytest.raises(asyncprawcore.BadRequest) as exception_info:
            await session.request(
                "PUT", "/api/v1/me/friends/spez", data={"note": "asyncprawcore"}
            )
        assert "reason" in (await exception_info.value.response.json())

    async def test_request__cloudflare_connection_timed_out(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
            await session.request("GET", "/")
            await session.request("GET", "/")
        assert exception_info.value.response.status == 522

    async def test_request__cloudflare_unknown_error(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
            await session.request("GET", "/")
            await session.request("GET", "/")
        assert exception_info.value.response.status == 520

    async def test_request__conflict(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
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

    async def test_request__created(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        response = await session.request("PUT", "/api/v1/me/friends/spez", data={})
        assert "name" in response

    async def test_request__forbidden(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        with pytest.raises(asyncprawcore.Forbidden):
            await session.request("GET", "/user/spez/gilded/given")

    async def test_request__gateway_timeout(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
        assert exception_info.value.response.status == 504

    async def test_request__get(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        params = {"limit": 100, "bool_param": True}
        response = await session.request("GET", "/", params=params)
        assert isinstance(response, dict)
        assert len(params) == 2
        assert response["kind"] == "Listing"

    async def test_request__internal_server_error(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
        assert exception_info.value.response.status == 500

    async def test_request__no_content(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        response = await session.request("DELETE", "/api/v1/me/friends/spez")
        assert response is None

    async def test_request__not_found(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.NotFound):
            await session.request("GET", "/r/pics/wiki/invalid")

    async def test_request__okay_with_0_byte_content(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        data = {"model": dumps({"name": "redditdev"})}
        path = f"/api/multi/user/{pytest.placeholders.username}/m/test"
        response = await session.request("DELETE", path, data=data)
        assert response == ""

    @pytest.mark.recorder_kwargs(match_requests_on=["method", "uri", "body"])
    async def test_request__patch(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        json = {"lang": "ja", "num_comments": 123}
        response = await session.request("PATCH", "/api/v1/me/prefs", json=json)
        assert response["lang"] == "ja"
        assert response["num_comments"] == 123

    async def test_request__post(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
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

    @pytest.mark.recorder_kwargs(match_requests_on=["uri", "method"])
    async def test_request__post__with_files(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
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

    async def test_request__raw_json(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        response = await session.request(
            "GET",
            "/r/reddit_api_test/comments/45xjdr/want_raw_json_test/",
        )
        assert (
            "WANT_RAW_JSON test: < > &"
            == response[0]["data"]["children"][0]["data"]["title"]
        )

    async def test_request__redirect(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.Redirect) as exception_info:
            await session.request("GET", "/r/random")
        assert exception_info.value.path.startswith("/r/")

    async def test_request__redirect_301(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.Redirect) as exception_info:
            await session.request("GET", "t/bird")
        assert exception_info.value.path == "/r/t:bird/"

    async def test_request__service_unavailable(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request("GET", "/")
            await session.request("GET", "/")
            await session.request("GET", "/")
        assert exception_info.value.response.status == 503

    async def test_request__too__many_requests__with_retry_headers(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
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
        assert (await exception_info.value.message()).startswith("\n<!doctype html>")

    async def test_request__too__many_requests__without_retry_headers(self, requestor):
        requestor._http.headers.update({"User-Agent": "python-requests/2.25.1"})
        authorizer = asyncprawcore.ReadOnlyAuthorizer(
            asyncprawcore.TrustedAuthenticator(
                requestor,
                pytest.placeholders.client_id,
                pytest.placeholders.client_secret,
            )
        )
        with pytest.raises(
            asyncprawcore.exceptions.ResponseException
        ) as exception_info:
            await authorizer.refresh()
        assert exception_info.value.response.status == 429
        assert not exception_info.value.response.headers.get("retry-after")
        assert exception_info.value.response.reason == "Too Many Requests"
        assert await exception_info.value.response.json() == {
            "message": "Too Many Requests",
            "error": 429,
        }

    @pytest.mark.recorder_kwargs(match_requests_on=["uri", "method"])
    async def test_request__too_large(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        data = {"upload_type": "header"}
        with open("tests/integration/files/too_large.jpg", "rb") as fp:
            files = {"file": fp}
            with pytest.raises(asyncprawcore.TooLarge) as exception_info:
                await session.request(
                    "POST",
                    "/r/asyncpraw/api/upload_sr_img",
                    data=data,
                    files=files,
                )
        assert exception_info.value.response.status == 413

    async def test_request__unavailable_for_legal_reasons(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        exception_class = asyncprawcore.UnavailableForLegalReasons
        with pytest.raises(exception_class) as exception_info:
            await session.request("GET", "/")
        assert exception_info.value.response.status == 451

    async def test_request__unsupported_media_type(
        self, script_authorizer: asyncprawcore.ScriptAuthorizer
    ):
        session = asyncprawcore.Session(script_authorizer)
        exception_class = asyncprawcore.SpecialError
        data = {
            "content": "type: submission\naction: upvote",
            "page": "config/automoderator",
        }
        with pytest.raises(exception_class) as exception_info:
            await session.request("POST", "r/asyncpraw/api/wiki/edit/", data=data)
        assert exception_info.value.response.status == 415

    async def test_request__uri_too_long(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        path_start = "/api/morechildren?link_id=t3_n7r3uz&children="
        with open("tests/integration/files/comment_ids.txt") as fp:
            ids = fp.read()
        with pytest.raises(asyncprawcore.URITooLong) as exception_info:
            await session.request("GET", (path_start + ids)[:9996])
        assert exception_info.value.response.status == 414

    async def test_request__with_insufficient_scope(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(
            trusted_authenticator, refresh_token=pytest.placeholders.refresh_token
        )
        await authorizer.refresh()
        session = asyncprawcore.Session(authorizer)
        with pytest.raises(asyncprawcore.InsufficientScope):
            await session.request("GET", "/api/v1/me")

    async def test_request__with_invalid_access_token(self, untrusted_authenticator):
        authorizer = asyncprawcore.ImplicitAuthorizer(
            untrusted_authenticator, None, 0, ""
        )
        session = asyncprawcore.Session(authorizer)
        session._authorizer.access_token = "invalid"
        with pytest.raises(asyncprawcore.InvalidToken):
            await session.request("get", "/")

    async def test_request__with_invalid_access_token__retry(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(readonly_authorizer)
        session._authorizer.access_token += "invalid"
        response = await session.request("GET", "/")
        assert isinstance(response, dict)
