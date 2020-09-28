#!/usr/bin/env python

"""This example outputs a user's list of trophies.

This program demonstrates the use of ``asyncprawcore.ReadOnlyAuthorizer`` that does
not require an access token to make authenticated requests to reddit.

"""
import os
import asyncprawcore
import sys
import asyncio


async def main():
    """Provide the program's entry point when directly executed."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} USERNAME")
        return 1

    requestor = asyncprawcore.Requestor("asyncprawcore_read_only_example")
    try:
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            os.environ["asyncprawcore_CLIENT_ID"],
            os.environ["asyncprawcore_CLIENT_SECRET"],
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

        return 0
    finally:
        await requestor.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    sys.exit(loop.run_until_complete(main()))
