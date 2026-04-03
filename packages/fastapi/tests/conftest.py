import pytest
import redis.asyncio as aioredis
from testcontainers.redis import RedisContainer


@pytest.fixture(scope="session")
def redis_container():
    with RedisContainer("redis:7-alpine") as container:
        yield container


@pytest.fixture
async def redis_client(redis_container):
    port = redis_container.get_exposed_port(6379)
    client = aioredis.from_url(f"redis://localhost:{port}")
    yield client
    await client.aclose()
