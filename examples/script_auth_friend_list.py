#!/usr/bin/env python

"""script_auth_friend_list.py outputs the authenticated user's list of friends.

This program demonstrates the use of ``asyncprawcore.ScriptAuthorizer``, which
enables those listed as a developer of the application to authenticate using
their username and password.

"""
import os
import asyncprawcore
import sys


def main():
    """Provide the program's entry point when directly executed."""
    authenticator = asyncprawcore.TrustedAuthenticator(
        asyncprawcore.Requestor("asyncprawcore_script_auth_example"),
        os.environ["asyncprawcore_CLIENT_ID"],
        os.environ["asyncprawcore_CLIENT_SECRET"],
    )
    authorizer = asyncprawcore.ScriptAuthorizer(
        authenticator,
        os.environ["asyncprawcore_USERNAME"],
        os.environ["asyncprawcore_PASSWORD"],
    )
    authorizer.refresh()

    with asyncprawcore.session(authorizer) as session:
        data = session.request("GET", "/api/v1/me/friends")

    for friend in data["data"]["children"]:
        print(friend["name"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
