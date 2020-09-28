#!/usr/bin/env python

"""This example outputs a user's list of trophies.

This program demonstrates the use of ``asyncprawcore.DeviceIDAuthorizer``.

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

    authenticator = asyncprawcore.UntrustedAuthenticator(
        asyncprawcore.Requestor("asyncprawcore_device_id_auth_example"),
        os.environ["asyncprawcore_CLIENT_ID"],
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
    loop = asyncio.get_event_loop()
    sys.exit(loop.run_until_complete(main()))
