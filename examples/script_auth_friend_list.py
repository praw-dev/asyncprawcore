#!/usr/bin/env python3

"""script_auth_friend_list.py outputs the authenticated user's list of friends.

This program demonstrates the use of ``asyncprawcore.ScriptAuthorizer``, which enables
those listed as a developer of the application to authenticate using their username and
password.

"""

import asyncio
import os
import sys

import asyncprawcore


async def main():
    """Provide the program's entry point when directly executed."""
    requestor = asyncprawcore.Requestor(user_agent="asyncprawcore_script_auth_example")

    try:
        authenticator = asyncprawcore.TrustedAuthenticator(
            client_id=os.environ["PRAWCORE_CLIENT_ID"],
            client_secret=os.environ["PRAWCORE_CLIENT_SECRET"],
            requestor=requestor,
        )
        authorizer = asyncprawcore.ScriptAuthorizer(
            authenticator=authenticator,
            username=os.environ["PRAWCORE_USERNAME"],
            password=os.environ["PRAWCORE_PASSWORD"],
        )
        await authorizer.refresh()

        async with asyncprawcore.session(authorizer=authorizer) as session:
            data = await session.request(method="GET", path="/api/v1/me/friends")

        for friend in data["data"]["children"]:
            print(friend["name"])
    finally:
        await requestor.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
