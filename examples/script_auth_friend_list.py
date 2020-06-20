#!/usr/bin/env python

"""script_auth_friend_list.py outputs the authenticated user's list of friends.

This program demonstrates the use of ``asyncprawcore.ScriptAuthorizer``, which
enables those listed as a developer of the application to authenticate using
their username and password.

"""
import os
import asyncprawcore
import sys
import asyncio


async def main():
    """Provide the program's entry point when directly executed."""
    requestor = asyncprawcore.Requestor("asyncprawcore_script_auth_example")

    try:
        authenticator = asyncprawcore.TrustedAuthenticator(
            requestor,
            os.environ["asyncprawcore_CLIENT_ID"],
            os.environ["asyncprawcore_CLIENT_SECRET"],
        )
        authorizer = asyncprawcore.ScriptAuthorizer(
            authenticator,
            os.environ["asyncprawcore_USERNAME"],
            os.environ["asyncprawcore_PASSWORD"],
        )
        await authorizer.refresh()

        async with asyncprawcore.session(authorizer) as session:
            data = await session.request("GET", "/api/v1/me/friends")

        for friend in data["data"]["children"]:
            print(friend["name"])

        return 0
    finally:
        await requestor.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    sys.exit(loop.run_until_complete(main()))
