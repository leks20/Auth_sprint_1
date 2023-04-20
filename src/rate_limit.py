import datetime
from redis_client import redis_client
from conf.config import settings


def limit_requests(user_id: str) -> bool | None:
    pipe = redis_client.pipeline()
    now = datetime.datetime.now()
    key = f'{user_id}:{now.minute}'

    pipe.incr(key, 1)
    pipe.expire(key, 59)

    result = pipe.execute()

    if result[0] > settings.request_limit_per_minute:
        return True