"""App-local runtime wiring for platform-api."""

from platform_api.runtime.memory import AppRuntime
from platform_api.runtime.wiring import create_runtime, get_runtime

__all__ = [
    "AppRuntime",
    "create_runtime",
    "get_runtime",
]
