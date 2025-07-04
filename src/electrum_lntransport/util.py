from functools import wraps
from asyncio import iscoroutinefunction, CancelledError
from logging import getLogger


_logger = getLogger('electrum_lntransport')


def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def log_exceptions(func):
    """Decorator to log AND re-raise exceptions."""
    assert iscoroutinefunction(func), 'func needs to be a coroutine'

    @wraps(func)
    async def wrapper(*args, **kwargs):
        self = args[0] if len(args) > 0 else None
        try:
            return await func(*args, **kwargs)
        except CancelledError as e:
            raise
        except BaseException as e:
            mylogger = self.logger if hasattr(self, 'logger') else _logger
            try:
                mylogger.exception(f"Exception in {func.__name__}: {repr(e)}")
            except BaseException as e2:
                print(f"logging exception raised: {repr(e2)}... orig exc: {repr(e)} in {func.__name__}")
            raise
    return wrapper
