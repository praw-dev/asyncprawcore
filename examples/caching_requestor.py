#!/usr/bin/env python

"""Example program that shows how simple in-memory caching can be used.

Demonstrates the use of custom sessions with :class:`.Requestor`. It's an adaptation of
``read_only_auth_trophies.py``.

"""

import asyncio
import os
import sys

import aiohttp

import asyncprawcore


class CachingSession(aiohttp.ClientSession):
    """Cache GETs in memory.

    Toy example of custom session to showcase the ``session`` parameter of
    :class:`.Requestor`.

    """

    get_cache = {}

    async def request(self, method, url, params=None, **kwargs):
        """Perform a request, or return a cached response if available."""
        params_key = tuple(params.items()) if params else ()
        if method.upper() == "GET" and (url, params_key) in self.get_cache:
            print("Returning cached response for:", method, url, params)
            return self.get_cache[(url, params_key)]
        result = await super().request(method, url, params=params, **kwargs)
        if method.upper() == "GET":
            self.get_cache[(url, params_key)] = result
            print("Adding entry to the cache:", method, url, params)
        return result


async def main():
    """Provide the program's entry point when directly executed."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} USERNAME")
        return 1

    caching_requestor = asyncprawcore.Requestor("asyncprawcore_device_id_auth_example", session=CachingSession())
    try:
        authenticator = asyncprawcore.TrustedAuthenticator(
            caching_requestor,
            os.environ["PRAWCORE_CLIENT_ID"],
            os.environ["PRAWCORE_CLIENT_SECRET"],
        )
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        await authorizer.refresh()

        user = sys.argv[1]

        async with asyncprawcore.session(authorizer) as session:
            data1 = await session.request("GET", f"/api/v1/user/{user}/trophies")

        async with asyncprawcore.session(authorizer) as session:
            data2 = await session.request("GET", f"/api/v1/user/{user}/trophies")

        for trophy in data1["data"]["trophies"]:
            description = trophy["data"]["description"]
            print(
                "Original:",
                trophy["data"]["name"] + (f" ({description})" if description else ""),
            )

        for trophy in data2["data"]["trophies"]:
            description = trophy["data"]["description"]
            print(
                "Cached:",
                trophy["data"]["name"] + (f" ({description})" if description else ""),
            )
        print(
            "----\nCached == Original:",
            data2["data"]["trophies"] == data2["data"]["trophies"],
        )
    finally:
        await caching_requestor.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
