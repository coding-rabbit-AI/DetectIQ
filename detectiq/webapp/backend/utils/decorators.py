from asyncio import get_event_loop, new_event_loop, set_event_loop
from functools import wraps

from asgiref.sync import async_to_sync
from rest_framework.decorators import action

from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)


def async_action(detail=False, methods=None, url_path=None):
    """Decorator to handle async actions in DRF viewsets."""

    def decorator(func):
        @action(detail=detail, methods=methods, url_path=url_path)
        @wraps(func)
        def wrapped(*args, **kwargs):
            try:
                loop = get_event_loop()
            except RuntimeError:
                loop = new_event_loop()
                set_event_loop(loop)
            return loop.run_until_complete(func(*args, **kwargs))

        return wrapped

    return decorator
