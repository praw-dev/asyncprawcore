#!/usr/bin/env python

"""This example outputs a user's list of trophies.

This program demonstrates the use of ``asyncprawcore.ReadOnlyAuthorizer`` that does not
require an access token to make authenticated requests to Reddit.

"""
import asyncio
import os
import sys

import asyncprawcore


async def main():
    """Provide the program's entry point when directly executed."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} USERNAME")
        return 1

    requestor = asyncprawcore.Requestor("asyncprawcore_read_only_example")
    try:
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            os.environ["PRAWCORE_CLIENT_ID"],
            os.environ["PRAWCORE_CLIENT_SECRET"],
        )
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        await authorizer.refresh()

        user = sys.argv[1]
        async with asyncprawcore.session(authorizer) as session:
            data = await session.request("GET", f"/api/v1/user/{user}/trophies")

        for trophy in data["data"]["trophies"]:
            description = trophy["data"]["description"]
            print(
                f"{trophy['data']['name']}{(f' ({description})' if description else '')}"
            )
    finally:
        await requestor.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
