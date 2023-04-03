import redis
from conf.config import settings

jwt_redis_blocklist = redis.StrictRedis(
    host=settings.redis_host,
    port=settings.redis_port,
    db=0,
    decode_responses=True,
)
