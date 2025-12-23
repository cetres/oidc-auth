"""
fastapi-oidc-middleware

A standalone, reusable Python library providing OIDC authentication and session
management for FastAPI and Starlette applications.

Designed for developers building multiple microservices, offering a drop-in
authentication solution to avoid code duplication.
"""

from .session import SessionStorage, InMemorySessionStore
from .middleware import OIDCAuthMiddleware
from .types import OIDCSettings
