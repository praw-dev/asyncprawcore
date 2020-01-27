#!/usr/bin/env python

"""This example outputs a user's list of trophies.

This program demonstrates the use of ``asyncprawcore.DeviceIDAuthorizer``.

"""

import os
import asyncprawcore
import sys


def main():
    """Provide the program's entry point when directly executed."""
    if len(sys.argv) != 2:
        print("Usage: {} USERNAME".format(sys.argv[0]))
        return 1

    authenticator = asyncprawcore.UntrustedAuthenticator(
        asyncprawcore.Requestor("asyncprawcore_device_id_auth_example"),
        os.environ["asyncprawcore_CLIENT_ID"],
    )
    authorizer = asyncprawcore.DeviceIDAuthorizer(authenticator)
    authorizer.refresh()

    user = sys.argv[1]
    with asyncprawcore.session(authorizer) as session:
        data = session.request("GET", "/api/v1/user/{}/trophies".format(user))

    for trophy in data["data"]["trophies"]:
        description = trophy["data"]["description"]
        print(
            trophy["data"]["name"]
            + (" ({})".format(description) if description else "")
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
