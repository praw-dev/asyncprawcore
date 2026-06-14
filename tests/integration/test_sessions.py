"""Test for asyncprawcore.Sessions module."""

import logging
from json import dumps
from pathlib import Path

import pytest

import asyncprawcore

from . import IntegrationTest


class TestSession(IntegrationTest):
    @pytest.fixture
    async def readonly_authorizer(self, trusted_authenticator):
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator=trusted_authenticator)
        await authorizer.refresh()
        return authorizer

    @pytest.fixture
    async def script_authorizer(self, trusted_authenticator):
        authorizer = asyncprawcore.ScriptAuthorizer(
            authenticator=trusted_authenticator,
            password=pytest.placeholders.password,
            username=pytest.placeholders.username,
        )
        await authorizer.refresh()
        return authorizer

    async def test_request__accepted(self, script_authorizer: asyncprawcore.ScriptAuthorizer, caplog):
        caplog.set_level(logging.DEBUG)
        session = asyncprawcore.Session(authorizer=script_authorizer)
        await session.request(method="POST", path="api/read_all_messages")
        found_message = False
        for package, level, message in caplog.record_tuples:
            if package == "asyncprawcore" and level == logging.DEBUG and "Response: 202 (2 bytes)" in message:
                found_message = True
        assert found_message, f"'Response: 202 (2 bytes)' in {caplog.record_tuples}"

    async def test_request__bad_gateway(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request(method="GET", path="/")
        assert exception_info.value.response.status == 502

    async def test_request__bad_json(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        with pytest.raises(asyncprawcore.BadJSON) as exception_info:
            await session.request(method="GET", path="/")
        assert exception_info.value.response.content_length == 1

    async def test_request__bad_request(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        with pytest.raises(asyncprawcore.BadRequest) as exception_info:
            await session.request(data={"note": "asyncprawcore"}, method="PUT", path="/api/v1/me/friends/spez")
        assert "reason" in (await exception_info.value.response.json())

    async def test_request__cloudflare_connection_timed_out(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError, check=lambda exception: exception.response.status == 522):
            await session.request(method="GET", path="/")

    async def test_request__cloudflare_unknown_error(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError, check=lambda exception: exception.response.status == 520):
            await session.request(method="GET", path="/")

    async def test_request__conflict(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        with pytest.raises(asyncprawcore.Conflict, check=lambda exception: exception.response.status == 409):
            await session.request(
                data={
                    "display_name": "sfwpornnetwork",
                    "from": "/user/kjoneslol/m/sfwpornnetwork",
                    "to": f"user/{pytest.placeholders.username}/m/sfwpornnetwork/",
                },
                method="POST",
                path="/api/multi/copy/",
            )

    async def test_request__created(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        response = await session.request(data="{}", method="PUT", path="/api/v1/me/friends/spez")
        assert "name" in response

    async def test_request__forbidden(self, script_authorizer: asyncprawcore.Authorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        with pytest.raises(asyncprawcore.Forbidden):
            await session.request(method="GET", path="/user/spez/upvoted")

    async def test_request__gateway_timeout(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError, check=lambda exception: exception.response.status == 504):
            await session.request(method="GET", path="/")

    async def test_request__get(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        params = {"bool_param": True, "limit": 100}
        response = await session.request(method="GET", params=params, path="/")
        assert isinstance(response, dict)
        assert len(params) == 2
        assert response["kind"] == "Listing"

    async def test_request__internal_server_error(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError, check=lambda exception: exception.response.status == 500):
            await session.request(method="GET", path="/")

    async def test_request__no_content(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        response = await session.request(method="DELETE", path="/api/v1/me/friends/spez")
        assert response is None

    async def test_request__not_found(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.NotFound):
            await session.request(method="GET", path="/r/pics/wiki/invalid")

    async def test_request__okay_with_0_byte_content(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        data = {"model": dumps({"name": "redditdev"})}
        path = f"/api/multi/user/{pytest.placeholders.username}/m/test"
        response = await session.request(data=data, method="DELETE", path=path)
        assert response == ""

    @pytest.mark.recorder_kwargs(match_requests_on=["method", "uri", "body"])
    async def test_request__patch(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        json = {"lang": "ja", "num_comments": 123}
        response = await session.request(json=json, method="PATCH", path="/api/v1/me/prefs")
        assert response["lang"] == "ja"
        assert response["num_comments"] == 123

    async def test_request__post(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        data = {
            "kind": "self",
            "sr": "asyncpraw",
            "text": "Test!",
            "title": "A Test from asyncprawcore.",
        }
        key_count = len(data)
        response = await session.request(data=data, method="POST", path="/api/submit")
        assert "a_test_from_asyncprawcore" in response["json"]["data"]["url"]
        assert key_count == len(data)  # Ensure data is untouched

    @pytest.mark.recorder_kwargs(match_requests_on=["uri", "method"])
    async def test_request__post__with_files(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        data = {"upload_type": "header"}
        with Path("tests/integration/files/white-square.png").open("rb") as fp:  # noqa: ASYNC230
            files = {"file": fp}
            response = await session.request(
                data=data,
                files=files,
                method="POST",
                path="/r/asyncpraw/api/upload_sr_img",
            )
        assert "img_src" in response

    async def test_request__raw_json(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        response = await session.request(
            method="GET",
            path="/r/reddit_api_test/comments/45xjdr/want_raw_json_test/",
        )
        assert response[0]["data"]["children"][0]["data"]["title"] == "WANT_RAW_JSON test: < > &"

    async def test_request__redirect(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.Redirect, check=lambda exception: exception.path.startswith("/r/")):
            await session.request(method="GET", path="/r/random")

    async def test_request__redirect_301(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.Redirect, check=lambda exception: exception.path == "/r/t:bird/"):
            await session.request(method="GET", path="t/bird")

    async def test_request__service_unavailable(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(asyncprawcore.ServerError) as exception_info:
            await session.request(method="GET", path="/")
        assert exception_info.value.response.status == 503

    async def test_request__too__many_requests__with_retry_headers(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        session.requestor._http.headers.update({"User-Agent": "python-requests/2.25.1"})
        with pytest.raises(asyncprawcore.TooManyRequests) as exception_info:
            await session.request(method="GET", path="/api/v1/me")
        assert exception_info.value.response.status == 429
        assert exception_info.value.response.headers.get("retry-after")
        assert exception_info.value.response.reason == "Too Many Requests"
        assert str(exception_info.value).startswith("received 429 HTTP response. Please wait at least")
        assert (await exception_info.value.message()).startswith("\n<!doctype html>")

    async def test_request__too__many_requests__without_retry_headers(self, requestor):
        requestor.headers.update({"User-Agent": "python-requests/2.25.1"})
        authorizer = asyncprawcore.ReadOnlyAuthorizer(
            authenticator=asyncprawcore.TrustedAuthenticator(
                client_id=pytest.placeholders.client_id,
                client_secret=pytest.placeholders.client_secret,
                requestor=requestor,
            )
        )
        with pytest.raises(asyncprawcore.exceptions.ResponseException) as exception_info:
            await authorizer.refresh()
        assert exception_info.value.response.status == 429
        assert not exception_info.value.response.headers.get("retry-after")
        assert exception_info.value.response.reason == "Too Many Requests"
        assert await exception_info.value.response.json() == {
            "error": 429,
            "message": "Too Many Requests",
        }

    @pytest.mark.recorder_kwargs(match_requests_on=["uri", "method"])
    async def test_request__too_large(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        data = {"upload_type": "header"}
        with Path("tests/integration/files/too_large.jpg").open("rb") as fp:  # noqa: ASYNC230
            files = {"file": fp}
            with pytest.raises(asyncprawcore.TooLarge, check=lambda exception: exception.response.status == 413):
                await session.request(
                    data=data,
                    files=files,
                    method="POST",
                    path="/r/asyncpraw/api/upload_sr_img",
                )

    async def test_request__unavailable_for_legal_reasons(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        with pytest.raises(
            asyncprawcore.UnavailableForLegalReasons, check=lambda exception: exception.response.status == 451
        ):
            await session.request(method="GET", path="/")

    async def test_request__unexpected_status_code(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        with pytest.raises(asyncprawcore.ResponseException, check=lambda exception: exception.response.status == 205):
            await session.request(method="DELETE", path="/api/v1/me/friends/spez")

    async def test_request__unsupported_media_type(self, script_authorizer: asyncprawcore.ScriptAuthorizer):
        session = asyncprawcore.Session(authorizer=script_authorizer)
        data = {
            "content": "type: submission\naction: upvote",
            "page": "config/automoderator",
        }
        with pytest.raises(asyncprawcore.SpecialError, check=lambda exception: exception.response.status == 415):
            await session.request(data=data, method="POST", path="r/asyncpraw/api/wiki/edit/")

    async def test_request__uri_too_long(self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        path_start = "/api/morechildren?link_id=t3_n7r3uz&children="
        ids = Path("tests/integration/files/comment_ids.txt").read_text()
        with pytest.raises(asyncprawcore.URITooLong, check=lambda exception: exception.response.status == 414):
            await session.request(method="GET", path=(path_start + ids)[:9996])

    async def test_request__with_insufficient_scope(self, trusted_authenticator):
        authorizer = asyncprawcore.Authorizer(
            authenticator=trusted_authenticator, refresh_token=pytest.placeholders.refresh_token
        )
        await authorizer.refresh()
        session = asyncprawcore.Session(authorizer=authorizer)
        with pytest.raises(asyncprawcore.InsufficientScope):
            await session.request(method="GET", path="/api/v1/me")

    async def test_request__with_invalid_access_token(self, untrusted_authenticator):
        authorizer = asyncprawcore.ImplicitAuthorizer(
            access_token=None, authenticator=untrusted_authenticator, expires_in=0, scope=""
        )
        session = asyncprawcore.Session(authorizer=authorizer)
        session._authorizer.access_token = "invalid"
        with pytest.raises(asyncprawcore.InvalidToken):
            await session.request(method="get", path="/")

    async def test_request__with_invalid_access_token__retry(
        self, readonly_authorizer: asyncprawcore.ReadOnlyAuthorizer
    ):
        session = asyncprawcore.Session(authorizer=readonly_authorizer)
        session._authorizer.access_token += "invalid"
        response = await session.request(method="GET", path="/")
        assert isinstance(response, dict)
