"""Constants for the asyncprawcore package."""
import os

__version__ = "2.0.1"

ACCESS_TOKEN_PATH = "/api/v1/access_token"
AUTHORIZATION_PATH = "/api/v1/authorize"
REVOKE_TOKEN_PATH = "/api/v1/revoke_token"
TIMEOUT = float(os.environ.get("prawcore_timeout", 16))
