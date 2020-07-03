.. _main_page:

asyncprawcore
=============

.. image:: https://img.shields.io/pypi/v/asyncprawcore.svg
   :alt: Latest asyncprawcore Version
   :target: https://pypi.python.org/pypi/asyncprawcore
.. image:: https://img.shields.io/pypi/pyversions/asyncprawcore
   :alt: Supported Python Versions
   :target: https://pypi.python.org/pypi/asyncprawcore
.. image:: https://coveralls.io/repos/github/praw-dev/asyncprawcore/badge.svg?branch=master
   :alt: Coveralls Coverage
   :target: https://coveralls.io/github/praw-dev/asyncprawcore?branch=master
.. image:: https://github.com/praw-dev/asyncprawcore/workflows/CI/badge.svg
   :alt: Github Actions Coverage
   :target: https://github.com/praw-dev/asyncprawcore/actions?query=branch%3Amaster


asyncprawcore is a low-level communication layer for PRAW 4+.

Installation
------------

Install asyncprawcore using ``pip`` via:

.. code-block:: console

    pip install asyncprawcore


Execution Example
-----------------

The following example demonstrates how to use asyncprawcore to obtain the list of
trophies for a given user using the script-app type.  This example assumes you
have the environment variables ``asyncprawcore_CLIENT_ID`` and
``asyncprawcore_CLIENT_SECRET`` set to the appropriate values for your application.

.. code-block:: python

    import os
    import pprint
    import asyncio
    import asyncprawcore

    async def main():
        authenticator = asyncprawcore.TrustedAuthenticator(
            asyncprawcore.Requestor('YOUR_VALID_USER_AGENT'),
            os.environ['asyncprawcore_CLIENT_ID'],
            os.environ['asyncprawcore_CLIENT_SECRET'])
        authorizer = asyncprawcore.ReadOnlyAuthorizer(authenticator)
        await authorizer.refresh()

        async with asyncprawcore.session(authorizer) as session:
            pprint.pprint(await session.request('GET', '/api/v1/user/bboe/trophies'))

    if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())

Save the above as ``trophies.py`` and then execute via:

.. code-block:: console

   python trophies.py

Additional examples can be found at:
https://github.com/praw-dev/asyncprawcore/tree/master/examples


Depending on asyncprawcore
--------------------------

asyncprawcore follows `semantic versioning <http://semver.org/>`_ with the exception
that deprecations will not be preceded by a minor release. In essence, expect
only major versions to introduce breaking changes to asyncprawcore's public
interface. As a result, if you depend on asyncprawcore then it is a good idea to
specify not only the minimum version of asyncprawcore your package requires, but to
also limit the major version.

Below are two examples of how you may want to specify your asyncprawcore dependency:

setup.py
~~~~~~~~

.. code-block:: python

   setup(...,
         install_requires=['asyncprawcore >=0.1, <1'],
         ...)

requirements.txt
~~~~~~~~~~~~~~~~

.. code-block:: text

   asyncprawcore >=1.5.1, <2
