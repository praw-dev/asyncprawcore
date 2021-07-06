Change Log
==========

2.2.1 (2021/07/06)
------------------

**Changed**

- Cast non-string objects to string when preprocessing ``data`` and ``params``.

2.2.0 (2021/06/15)
------------------

**Added**

- Support 202 "Accepted" HTTP responses.

**Fixed**

- The expected HTTP response status code for a request made with the proper credentials
  to api/v1/revoke_token has been changed from 204 to 200.

2.1.0 (2021/06/15)
------------------

**Added**

- Add a ``URITooLarge`` exception.
- :class:`.ScriptAuthorizer` has a new parameter ``two_factor_callback `` that supplies
  OTPs (One-Time Passcodes) when :meth:`.ScriptAuthorizer.refresh` is called.
- Add a ``TooManyRequests`` exception.

**Fixed**

- Fix ``RuntimeWarning`` when executing pre/post refresh token callbacks.

2.0.0 (2021-02-23)
------------------

**Added**

- ``Authorizer`` optionally takes a ``pre_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of ``Authorizer`` prior to
  refreshing the access and refresh tokens.
- ``Authorizer`` optionally takes a ``post_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of ``Authorizer`` after
  refreshing the access and refresh tokens.

**Changed**

- The ``refresh_token`` argument to ``Authorizer`` must now be passed by keyword, and
  cannot be passed as a positional argument.

1.5.1 (2021-01-25)
------------------

**Changed**

- Improved preprocessing for ``data`` and ``params`` in ``Session.request()``.

1.5.0 (2020-09-28)
------------------

**Changed**

- Added preprocessing for ``data`` and ``params`` in ``asyncprawcore.Session.request()``
  for compatibility with ``aiohttp``.

**Fixed**

- Keys with a ``None`` value in the ``data`` or ``params`` parameters for
  ``asyncprawcore.Session.request()`` are now dropped as
  ``aiohttp.ClientSession.request()`` does not accept ``None`` values in ``data`` and
  ``params``.
- Keys with a boolean value in the ``params`` parameter for
  ``asyncprawcore.Session.request()`` are now casted to a string as
  ``aiohttp.ClientSession.request()`` does not accept boolean values in ``params``.

1.4.0.post2 (2020-07-12)
------------------------

**Fixed**

- How files are handled. ``data`` is now able to be passed with ``files`` since
  asyncpraw can make requests with both parameters.
- Fixed ``SpecialException`` not able to get ``response.json()`` since it is a
  coroutine.

1.4.0.post1 (2020-07-03)
------------------------

**Fixed**

- Documentation errors.
- ``authorize_url`` will correctly return a ``str`` instead of ``yarl.URL()``.

1.4.0 (2020-06-20)
------------------

- Converted from ``requests`` to ``aiohttp`` for asynchronous operation.
- Updated upto version 1.4.0 of prawcore.
- Forked from `praw-dev/prawcore <https://github.com/praw-dev/prawcore>`_
