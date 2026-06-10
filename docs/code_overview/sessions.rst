##########
 Sessions
##########

A :class:`.Session` ties an authorizer to a requestor and exposes the
:meth:`.Session.request` method that Async PRAW uses to communicate with Reddit. The
:func:`.session` helper is the recommended way to construct one.

.. autofunction:: asyncprawcore.sessions.session

.. autoclass:: asyncprawcore.sessions.Session
    :inherited-members:
