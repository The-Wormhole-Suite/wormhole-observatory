from pihole6api.client import PiHole6Client
from pihole6api.connection import PiHole6Connection, normalize_api_url
from pihole6api.errors import (
    PiHole6AuthenticationError,
    PiHole6ConnectionError,
    PiHole6Error,
    PiHole6HTTPError,
)
from pihole6api.health import ConnectionHealth, ConnectionState

__all__ = [
    "ConnectionHealth",
    "ConnectionState",
    "PiHole6AuthenticationError",
    "PiHole6Client",
    "PiHole6Connection",
    "PiHole6ConnectionError",
    "PiHole6Error",
    "PiHole6HTTPError",
    "normalize_api_url",
]
