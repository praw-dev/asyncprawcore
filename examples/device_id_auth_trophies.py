#!/usr/bin/env python

"""Example program that outputs a user's list of trophies.

This program demonstrates the use of ``asyncprawcore.DeviceIDAuthorizer``.

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

    authenticator = asyncprawcore.UntrustedAuthenticator(
        asyncprawcore.Requestor("asyncprawcore_device_id_auth_example"),
        os.environ["PRAWCORE_CLIENT_ID"],
    )
    authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator)
    await authorizer.refresh()

    user = sys.argv[1]
    async with asyncprawcore.session(authorizer) as session:
        data = await session.request("GET", f"/api/v1/user/{user}/trophies")

    for trophy in data["data"]["trophies"]:
        description = trophy["data"]["description"]
        print(trophy["data"]["name"] + (f" ({description})" if description else ""))

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
