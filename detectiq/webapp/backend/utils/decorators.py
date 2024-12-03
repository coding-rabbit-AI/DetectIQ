from asyncio import get_event_loop, set_event_loop
from functools import wraps

from asgiref.sync import async_to_sync
from rest_framework.decorators import action

from detectiq.core.utils.logging import get_logger

logger = get_logger(__name__)


def async_action(detail=False, methods=None, url_path=None, **kwargs):
    """Decorator to handle async actions in DRF viewsets."""

    def decorator(func):
        @action(detail=detail, methods=methods, url_path=url_path, **kwargs)
        @wraps(func)
        def wrapped(viewset, request, *args, **kwargs):
            try:
                # Set new event loop for this thread
                loop = get_event_loop()
                set_event_loop(loop)

                # Run the async function and get result
                result = async_to_sync(func)(viewset, request, *args, **kwargs)

                # Clean up
                loop.close()
                return result

            except Exception as e:
                logger.error(f"Error in async action: {str(e)}")
                raise

        return wrapped

    return decorator
