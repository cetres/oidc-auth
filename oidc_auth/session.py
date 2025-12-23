"""
Session Storage Protocol

This module defines the abstract interface (Protocol) for session management.
It ensures that any session storage implementation adheres to a common
dictionary-like contract, allowing for flexible and swappable session
persistence mechanisms (e.g., in-memory, Redis, Memcached).
"""

from typing import Protocol, Dict, Any, MutableMapping

class SessionStorage(Protocol, MutableMapping[str, Dict[str, Any]]):
    """
    Abstract base class defining the interface for session storage.

    Implementations of this protocol must provide a dictionary-like interface
    for storing and retrieving session data. This allows the OIDC middleware
    to interact with various session backends in a consistent manner.

    The session data for a given session ID should be a dictionary
    (Dict[str, Any]).
    """
    def __getitem__(self, key: str) -> Dict[str, Any]:
        ...

    def __setitem__(self, key: str, value: Dict[str, Any]) -> None:
        ...

    def __delitem__(self, key: str) -> None:
        ...

    def __len__(self) -> int:
        ...

    def __iter__(self) -> 'Iterator[str]': # type: ignore
        ...

class InMemorySessionStore(dict, SessionStorage):
    """
    A default in-memory session storage implementation.

    This class inherits from `dict`, providing a simple, dictionary-like
    backend for storing session data. It is suitable for single-process
    applications and development environments.
    """
    pass
