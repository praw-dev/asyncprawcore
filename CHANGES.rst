Change Log
==========

asyncprawcore follows `semantic versioning <http://semver.org/>`_ with the
exception that deprecations will not be announced by a minor release.

1.4.0.post2 (2020-07-12)
------------------------

**Fixed**

* How files are handled. ``data`` is now able to be passed with ``files`` since
    asyncpraw can make requests with both parameters.
* Fixed ``SpecialException`` not able to get ``response.json()`` since it is a coroutine.

1.4.0.post1 (2020-07-03)
------------------------

**Fixed**

* Documentation errors
* ``authorize_url`` will correctly return a ``str`` instead of ``yarl.URL()``.

1.4.0 (2020-06-20)
------------------

* Converted from ``requests`` to ``aiohttp`` for asynchronous operation
* Updated upto version 1.4.0 of prawcore
* Forked from `praw-dev/prawcore <https://github.com/praw-dev/prawcore>`_