import redis
from conf.config import settings

redis_client = redis.StrictRedis(
    host=settings.redis_host,
    port=settings.redis_port,
    db=0,
    decode_responses=True,
)

