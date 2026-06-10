################
 Authentication
################

asyncprawcore separates authentication into two responsibilities:

- **Authenticators** identify your registered Reddit application.
- **Authorizers** use an authenticator to obtain and refresh the OAuth2 access tokens
  that authorize individual requests.

****************
 Authenticators
****************

.. autoclass:: asyncprawcore.auth.BaseAuthenticator
    :inherited-members:

.. autoclass:: asyncprawcore.auth.TrustedAuthenticator
    :inherited-members:

.. autoclass:: asyncprawcore.auth.UntrustedAuthenticator
    :inherited-members:

*************
 Authorizers
*************

.. autoclass:: asyncprawcore.auth.BaseAuthorizer
    :inherited-members:

.. autoclass:: asyncprawcore.auth.Authorizer
    :inherited-members:

.. autoclass:: asyncprawcore.auth.DeviceIDAuthorizer
    :inherited-members:

.. autoclass:: asyncprawcore.auth.ImplicitAuthorizer
    :inherited-members:

.. autoclass:: asyncprawcore.auth.ReadOnlyAuthorizer
    :inherited-members:

.. autoclass:: asyncprawcore.auth.ScriptAuthorizer
    :inherited-members:
