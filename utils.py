
import time
from typing import Callable, TypeVar

T = TypeVar('T')

def retry(times: int = 3, wait_s: float = 0.5):
    def deco(fn: Callable[..., T]) -> Callable[..., T]:
        def inner(*a, **kw):
            last = None
            for i in range(times):
                try:
                    return fn(*a, **kw)
                except Exception as e:
                    last = e
                    if i < times - 1:
                        time.sleep(wait_s)
            raise last
        return inner
    return deco
