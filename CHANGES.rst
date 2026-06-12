############
 Change Log
############

asyncprawcore follows `semantic versioning <https://semver.org/>`_.

************
 Unreleased
************

**Changed**

- Make every public parameter either keyword-only or positional-only. The ``requestor``,
  ``authenticator``, and ``authorizer`` subjects of the authenticator and authorizer
  classes, the parameters of :class:`.Requestor`, :meth:`.Session.request`, and
  :meth:`.BaseAuthenticator.authorize_url`, the ``only_access`` argument of
  :meth:`.Authorizer.revoke`, and the ``session`` factory are now keyword-only, while
  the single obvious operand of a method (such as the ``token`` argument of
  :meth:`.BaseAuthenticator.revoke_token`, the ``code`` argument of
  :meth:`.Authorizer.authorize`, and the ``response`` argument of the exception classes)
  is positional-only.

**Removed**

- The deprecated ``loop`` argument of :class:`.Requestor`, which has been ignored since
  2.5.0.

********************
 3.1.0 (2026/06/10)
********************

**Added**

- Support for Python 3.14.
- Add an ``__all__`` to the ``asyncprawcore`` package to explicitly define its public
  API.
- Add a ``py.typed`` marker (:PEP:`561`) so that downstream projects can type check
  against asyncprawcore's inline annotations.
- Add read-only :attr:`.Session.authorizer`, :attr:`.Session.rate_limiter`, and
  :attr:`.Session.requestor` properties, a :attr:`.BaseAuthorizer.authenticator`
  property, and a :attr:`.BaseAuthenticator.requestor` property, so that downstream code
  can reach these objects without accessing protected attributes.
- Add Sphinx-based documentation, published at https://asyncprawcore.readthedocs.io/.

**Changed**

- Improved exception message when ``asyncio.TimeoutError`` is raised.
- Improve source docstrings and type annotations so that references render cleanly in
  the new documentation.
- Fixed type hinting for ``data`` and ``params`` in ``Requestor.request()``.
- Pass ``files`` to ``aiohttp.ClientSession.request()`` in ``Requestor.request()``
  correctly again.
- Widen the ``authorizer`` parameter of :func:`.session` to ``BaseAuthorizer`` to match
  :class:`.Session`, so that passing an :class:`.ImplicitAuthorizer` or
  :class:`.DeviceIDAuthorizer` type checks.
- Widen the ``data``, ``files``, ``json``, and ``params`` parameter annotations of
  :meth:`.Session.request` to reflect the values it already accepts at runtime (for
  example a non-dict ``data`` body, a ``list`` ``json`` payload, and any ``IO`` file
  object), so that callers no longer need to cast these arguments.

**Removed**

- Support for Python 3.9, which is end-of-life on 2025-10-31.

********************
 3.0.2 (2025/08/06)
********************

**Changed**

- Improved type hinting.

********************
 3.0.1 (2025/08/02)
********************

**Fixed**

- Increase half-second delay introduced in ``3.0.0`` to a full second delay.

********************
 3.0.0 (2025/08/02)
********************

**Changed**

- Session creation is now delayed and existing sessions will be reused.
- Drop support for Python 3.8, which was end-of-life on 2024-10-07.
- :class:`.RateLimiter` attribute ``next_request_timestamp`` has been removed and
  replaced with ``next_request_timestamp_ns``.

**Fixed**

- Add a half-second delay when there are no more requests in the rate limit window and
  the window has zero seconds remaining to avoid a semi-rare case where Reddit will
  return a 429 response resulting in a :class:`.TooManyRequests` exception.

**Removed**

- Remove :class:`.RateLimiter` attribute ``reset_timestamp``.

********************
 2.4.0 (2023/11/27)
********************

**Changed**

- Drop support for Python 3.6, which was end-of-life on 2021-12-23.
- :class:`.DeviceIDAuthorizer` can be now used with :class:`.TrustedAuthenticator`.
- Updated rate limit algorithm to better handle Reddit's new rate limits.
- Drop support for Python 3.7, which was end-of-life on 2023-06-27.

********************
 2.3.0 (2021/07/27)
********************

**Added**

- 301 redirects result in a ``Redirect`` exception.
- :class:`.Requestor` is now initialized with a ``timeout`` parameter.
- :class:`.ScriptAuthorizer`, :class:`.ReadOnlyAuthorizer`, and
  :class:`.DeviceIDAuthorizer` have a new parameter, ``scopes``, which determines the
  scope of access requests.
- Retry 408 "Request Timeout" HTTP responses.

********************
 2.2.1 (2021/07/06)
********************

**Changed**

- Cast non-string objects to string when preprocessing ``data`` and ``params``.

********************
 2.2.0 (2021/06/15)
********************

**Added**

- Support 202 "Accepted" HTTP responses.

**Fixed**

- The expected HTTP response status code for a request made with the proper credentials
  to api/v1/revoke_token has been changed from 204 to 200.

********************
 2.1.0 (2021/06/15)
********************

**Added**

- Add a :class:`.URITooLong` exception.
- :class:`.ScriptAuthorizer` has a new parameter ``two_factor_callback`` that supplies
  OTPs (One-Time Passcodes) when :meth:`.ScriptAuthorizer.refresh` is called.
- Add a :class:`.TooManyRequests` exception.

**Fixed**

- Fix ``RuntimeWarning`` when executing pre/post refresh token callbacks.

********************
 2.0.0 (2021-02-23)
********************

**Added**

- :class:`.Authorizer` optionally takes a ``pre_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of :class:`.Authorizer` prior to
  refreshing the access and refresh tokens.
- :class:`.Authorizer` optionally takes a ``post_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of :class:`.Authorizer` after
  refreshing the access and refresh tokens.

**Changed**

- The ``refresh_token`` argument to :class:`.Authorizer` must now be passed by keyword,
  and cannot be passed as a positional argument.

********************
 1.5.1 (2021-01-25)
********************

**Changed**

- Improved preprocessing for ``data`` and ``params`` in ``Session.request()``.

********************
 1.5.0 (2020-09-28)
********************

**Added**

- :meth:`.Requestor.request` can be given a timeout parameter to control the amount of
  time to wait for a request to succeed.

**Changed**

- Added preprocessing for ``data`` and ``params`` in ``asyncprawcore.Session.request()``
  for compatibility with ``aiohttp``.

**Fixed**

:class:`.RateLimiter` will not sleep longer than ``next_request_timestamp``.

**Fixed**

- Keys with a ``None`` value in the ``data`` or ``params`` parameters for
  ``asyncprawcore.Session.request()`` are now dropped as
  ``aiohttp.ClientSession.request()`` does not accept ``None`` values in ``data`` and
  ``params``.
- Keys with a boolean value in the ``params`` parameter for
  ``asyncprawcore.Session.request()`` are now casted to a string as
  ``aiohttp.ClientSession.request()`` does not accept boolean values in ``params``.

**************************
 1.4.0.post2 (2020-07-12)
**************************

**Fixed**

- How files are handled. ``data`` is now able to be passed with ``files`` since
  asyncpraw can make requests with both parameters.
- Fixed ``SpecialException`` not able to get ``response.json()`` since it is a
  coroutine.

**************************
 1.4.0.post1 (2020-07-03)
**************************

**Fixed**

- Documentation errors.
- ``authorize_url`` will correctly return a ``str`` instead of ``yarl.URL()``.

********************
 1.4.0 (2020-06-20)
********************

- Converted from ``requests`` to ``aiohttp`` for asynchronous operation.
- Updated upto version 1.4.0 of prawcore.
- Forked from `praw-dev/prawcore <https://github.com/praw-dev/prawcore>`_
