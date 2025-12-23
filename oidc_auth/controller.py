from typing import Dict, Optional
import uuid

import httpx
from fastapi import Request
from fastapi.responses import RedirectResponse, JSONResponse

from oidc_auth.types import OIDCSettings
from oidc_auth.session import SessionStorage

# --- 1. The Controller (Shared Logic) ---
class OIDCController:
    """
    Handles the core OpenID Connect (OIDC) authentication business logic.

    This standalone class encapsulates the OIDC flow, managing login
    redirection, authorization code exchange, token retrieval, user information
    fetching, and session management. It is designed to be framework-agnostic
    to promote reusability across various Python web applications.

    Attributes:
        config (OIDCSettings): An instance of OIDCSettings containing OIDC
                               client configuration, including client_id,
                               client_secret, authorize_url, token_url,
                               userinfo_url, scope, and redirect_uri.
        session_store (SessionStorage): An object that implements the SessionStorage
                                        protocol for storing session data.
    """
    def __init__(self, config: OIDCSettings, session_store: SessionStorage):
        """
        Initializes the OIDCController with configuration and session storage.

        Args:
            config (OIDCSettings): An instance of OIDCSettings containing OIDC
                                   client configuration (e.g., CLIENT_ID,
                                   CLIENT_SECRET, AUTHORIZE_URL, etc.).
            session_store (SessionStorage): An object adhering to the
                                            SessionStorage protocol for
                                            persisting session data.
        """
        self.config = config
        self.session_store = session_store

    async def login(self, request: Request):
        """
        Initiates the OIDC login process.

        Constructs the authorization request URL with necessary parameters
        (client ID, response type, scope, redirect URI, and a unique state)
        and returns a RedirectResponse to the OIDC provider's authorization endpoint.

        Args:
            request (Request): The incoming FastAPI/Starlette request object.

        Returns:
            RedirectResponse: A response that redirects the user's browser
                              to the OIDC provider for authentication.
        """
        params = {
            "client_id": self.config.CLIENT_ID,
            "response_type": "code",
            "scope": self.config.SCOPE,
            "redirect_uri": self.config.REDIRECT_URI,
            "state": str(uuid.uuid4()),
        }
        query = "&".join([f"{k}={v}" for k, v in params.items()])
        return RedirectResponse(f"{self.config.AUTHORIZE_URL}?{query}")

    async def callback(self, request: Request):
        """
        Handles the OIDC callback from the identity provider.

        Upon successful authentication, the OIDC provider redirects the user
        back to this endpoint with an authorization code. This method
        exchanges the code for access and ID tokens, fetches user information
        using the access token, and stores relevant user and token data in the
        session store. It then redirects the user to the application's root.

        Args:
            request (Request): The incoming FastAPI/Starlette request object.

        Returns:
            JSONResponse: An error response if the code is missing or token
                          exchange fails.
            RedirectResponse: A response that redirects the user to the
                              application's root page after successful login
                              and sets a session cookie.
        """
        code = request.query_params.get("code")
        if not code:
            return JSONResponse({"error": "Missing code"}, status_code=400)

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                self.config.TOKEN_URL,
                data={
                    "client_id": self.config.CLIENT_ID,
                    "client_secret": self.config.CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.config.REDIRECT_URI,
                },
                headers={"Accept": "application/json"}
            )
            
            if token_resp.status_code != 200:
                return JSONResponse({"error": "Failed to get token"}, status_code=400)
            
            tokens = token_resp.json()
            access_token = tokens.get("access_token")

            user_resp = await client.get(
                self.config.USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            user_info = user_resp.json()

            # Persistence
            session_id = str(uuid.uuid4())
            self.session_store[session_id] = {
                "user": user_info,
                "access_token": access_token
            }
            
            response = RedirectResponse(url="/")
            response.set_cookie(
                key="session_id", 
                value=session_id, 
                httponly=True, 
                secure=self.config.COOKIE_SECURE, 
                samesite=self.config.COOKIE_SAMESITE
            )
            return response

    async def logout(self, request: Request):
        """
        Handles user logout.

        Invalidates the user's session by removing their data from the
        session store and clears the session cookie from the user's browser.
        After logout, the user is redirected to the login page.

        Args:
            request (Request): The incoming FastAPI/Starlette request object.

        Returns:
            RedirectResponse: A response that redirects the user to the
                              login page after successful logout and clears
                              the session cookie.
        """
        session_id = request.cookies.get("session_id")
        if session_id and session_id in self.session_store:
            del self.session_store[session_id]
            
        response = RedirectResponse(url="/login")
        response.delete_cookie("session_id")
        return response
    
    async def exchange_token(self, session_id: str, target_client: str) -> Optional[str]:
        """
        Performs an OIDC token exchange (On-Behalf-Of flow).

        This method exchanges the user's current access token for a new token
        that is scoped for a different client or audience (the `target_client`).
        This is useful for service-to-service calls where the downstream service
        needs to verify the original user's identity.

        Note: This requires the OIDC provider to support the token exchange
        grant type (RFC 8693).

        Args:
            session_id (str): The ID of the current user's session, used to retrieve
                              the subject token from the session store.
            target_client (str): The identifier (e.g., client ID or audience URI)
                                 of the target service for which the new token is intended.

        Returns:
            Optional[str]: The newly obtained access token if the exchange is
                           successful, otherwise None.
        """
        if session_id not in self.session_store:
            return None

        subject_token = self.session_store[session_id].get("access_token")
        if not subject_token:
            return None

        async with httpx.AsyncClient() as client:
            exchange_resp = await client.post(
                self.config.TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": self.config.CLIENT_ID,
                    "client_secret": self.config.CLIENT_SECRET,
                    "subject_token": subject_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "audience": target_client,
                },
                headers={"Accept": "application/json"}
            )

            if exchange_resp.status_code != 200:
                # Optionally log the error from exchange_resp.json()
                return None
            
            new_tokens = exchange_resp.json()
            return new_tokens.get("access_token")
