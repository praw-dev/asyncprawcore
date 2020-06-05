Change Log
==========

asyncprawcore follows `semantic versioning <http://semver.org/>`_ with the
exception that deprecations will not be announced by a minor release.


1.4.0 (2020-05-28)
------------------

**Added**

* When calling :meth:`.Session.request`, we add the key-value pair
  ``"api_type": "json"`` to the ``json`` parameter, if it is a ``dict``.

**Changed**

* (Non-breaking) Requests to ``www.reddit.com`` use the ``Connection: close``
  header to avoid warnings when tokens are refreshed after their one-hour
  expiration.


1.3.0 (2020-04-23)
------------------

**Added**

* All other requestor methods, most notably :meth:`.Session.request`, now contain
  a ``timeout`` parameter.


1.2.0 (2020-04-23)
------------------

**Added**

* Method ``Requestor.request`` can be given a timeout parameter to 
  control the amount of time to wait for a request to succeed.

**Changed**

* Updated rate limit algorithm to more intelligently rate limit when there
  are extra requests remaining.

* Forked from `praw-dev/prawcore <https://github.com/praw-dev/prawcore>`_