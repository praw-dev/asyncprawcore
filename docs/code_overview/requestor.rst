###########
 Requestor
###########

The :class:`.Requestor` is the lowest-level component in asyncprawcore. It wraps an
:class:`aiohttp.ClientSession` and is responsible for issuing the actual HTTP requests
to Reddit. Subclass it to customize request behavior, for example to add caching or
logging.

.. autoclass:: asyncprawcore.requestor.Requestor
    :inherited-members:
