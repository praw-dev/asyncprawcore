Change Log
==========

asyncprawcore follows `semantic versioning <http://semver.org/>`_.

Unreleased
----------

**Changed**

- Drop support for Python 3.6, which is end-of-life on 2021-12-23.
- :class:`DeviceIDAuthorizer` can be now used with :class:`TrustedAuthenticator`.
- Updated rate limit algorithm to better handle reddit's new rate limits.

2.3.0 (2021/07/27)
------------------

**Added**

- 301 redirects result in a ``Redirect`` exception.
- :class:`Requestor` is now initialized with a ``timeout`` parameter.
- :class:`ScriptAuthorizer`, :class:`ReadOnlyAuthorizer`, and
  :class:`DeviceIDAuthorizer` have a new parameter, ``scopes``, which determines the
  scope of access requests.
- Retry 408 "Request Timeout" HTTP responses.

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

- Add a :class:`URITooLarge` exception.
- :class:`ScriptAuthorizer` has a new parameter ``two_factor_callback`` that supplies
  OTPs (One-Time Passcodes) when :meth:`.ScriptAuthorizer.refresh` is called.
- Add a :class:`TooManyRequests` exception.

**Fixed**

- Fix ``RuntimeWarning`` when executing pre/post refresh token callbacks.

2.0.0 (2021-02-23)
------------------

**Added**

- :class:`Authorizer` optionally takes a ``pre_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of :class:`Authorizer` prior to
  refreshing the access and refresh tokens.
- :class:`Authorizer` optionally takes a ``post_refresh_callback`` keyword argument. If
  provided, the function will called with the instance of :class:`Authorizer` after
  refreshing the access and refresh tokens.

**Changed**

- The ``refresh_token`` argument to :class:`Authorizer` must now be passed by keyword,
  and cannot be passed as a positional argument.

1.5.1 (2021-01-25)
------------------

**Changed**

- Improved preprocessing for ``data`` and ``params`` in ``Session.request()``.

1.5.0 (2020-09-28)
------------------

**Added**

- :meth:`.Requestor.request` can be given a timeout parameter to control the amount of
  time to wait for a request to succeed.

**Changed**

- Added preprocessing for ``data`` and ``params`` in ``asyncprawcore.Session.request()``
  for compatibility with ``aiohttp``.

**Fixed**

:class:`RateLimiter` will not sleep longer than ``next_request_timestamp``.

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
