"""Test asyncprawcore."""
import asyncio


async def _sleep(*args):
    pass


asyncio.sleep = _sleep
