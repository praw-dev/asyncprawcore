"""Constants for the asyncprawcore package."""
import os

__version__ = "1.4.0"

ACCESS_TOKEN_PATH = "/api/v1/access_token"
AUTHORIZATION_PATH = "/api/v1/authorize"
REVOKE_TOKEN_PATH = "/api/v1/revoke_token"
TIMEOUT = float(os.environ.get("asyncprawcore_timeout", 16))
