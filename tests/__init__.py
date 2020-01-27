"""Test asyncprawcore."""
import time
from .conftest import VCR


time.sleep = lambda x: None
