"""
FastAPI Application Example

This module demonstrates how to integrate the OIDCAuthMiddleware and OIDCController
into a FastAPI application. It sets up a basic FastAPI app with OIDC authentication
and defines protected and public routes.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import RedirectResponse

from oidc_auth.controller import OIDCController
from oidc_auth.middleware import OIDCAuthMiddleware
from oidc_auth.session import InMemorySessionStore
from oidc_auth.types import OIDCSettings

# Use the default in-memory session store
session_store = InMemorySessionStore()

# Load OIDC Configuration using Pydantic BaseSettings
settings = OIDCSettings()

app = FastAPI(
    title="FastAPI OIDC Example",
    description="A demonstration of OIDC authentication with FastAPI using oidc-auth middleware.",
    version="1.0.0"
)

# Initialize OIDCController
oidc_controller = OIDCController(config=settings, session_store=session_store)

# Add OIDCAuthMiddleware to the FastAPI application
# Public paths are those that do not require authentication
app.add_middleware(
    OIDCAuthMiddleware,
    controller=oidc_controller,
    public_paths=["/", "/public", "/login", "/oidc/callback", "/oidc/logout"]
)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    Root endpoint. Accessible to both authenticated and unauthenticated users.
    Displays user information if authenticated.
    """
    user_info = request.state.user
    if user_info:
        email = user_info.get("email", "N/A")
        return f"""
        <html>
            <head>
                <title>Welcome</title>
            </head>
            <body>
                <h1>Welcome, {email}!</h1>
                <p>This is a protected page. You are logged in.</p>
                <p><a href="/protected">Go to protected content</a></p>
                <p><a href="/api/downstream">Call Downstream API (Token Exchange)</a></p>
                <p><a href="/oidc/logout">Logout</a></p>
                <p><a href="/public">Go to public content</a></p>
            </body>
        </html>
        """
    return """
    <html>
        <head>
            <title>Welcome</title>
        </head>
        <body>
            <h1>Welcome!</h1>
            <p>You are not logged in.</p>
            <p><a href="/login">Login with OIDC</a></p>
            <p><a href="/public">Go to public content</a></p>
        </body>
    </html>
    """

@app.get("/protected", response_class=HTMLResponse)
async def protected_route(request: Request):
    """
    A protected endpoint. Only accessible to authenticated users.
    """
    user_info = request.state.user
    if user_info:
        email = user_info.get("email", "N/A")
        return f"""
        <html>
            <head>
                <title>Protected Content</title>
            </head>
            <body>
                <h1>Protected Content for {email}</h1>
                <p>This content is only visible if you are authenticated.</p>
                <p><a href="/">Go to home</a></p>
                <p><a href="/oidc/logout">Logout</a></p>
            </body>
        </html>
        """
    return RedirectResponse(url="/login") # Should ideally not be reached due to middleware protection

@app.get("/public", response_class=HTMLResponse)
async def public_route():
    """
    A public endpoint. Accessible to all users, authenticated or not.
    """
    return """
    <html>
        <head>
            <title>Public Content</title>
        </head>
        <body>
            <h1>Public Content</h1>
            <p>This content is accessible to everyone.</p>
            <p><a href="/">Go to home</a></p>
        </body>
    </html>
    """

# Example of a protected API endpoint
@app.get("/api/data")
async def get_api_data(request: Request):
    """
    An example API endpoint that requires authentication.
    """
    if request.state.user:
        return {"message": "This is sensitive API data", "user": request.state.user}
    # The middleware should handle unauthorized access with a 401 JSONResponse
    return {"message": "You should not see this if unauthenticated"}

@app.get("/api/downstream")
async def call_downstream_api(request: Request):
    """
    An example endpoint that demonstrates OIDC token exchange (On-Behalf-Of flow).
    """
    if not request.state.user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    session_id = request.cookies.get("session_id")
    if not session_id:
        return JSONResponse({"error": "Missing session"}, status_code=400)

    # The identifier for the downstream API you want to call.
    # This must be a known client ID or audience URI to the OIDC provider.
    target_client_id = "downstream-api-client-id" 

    exchanged_token = await oidc_controller.exchange_token(session_id, target_client_id)

    if exchanged_token:
        # In a real application, you would use this token to call the downstream API.
        # For demonstration, we'll just return it.
        return {
            "message": "Successfully exchanged token for downstream API.",
            "downstream_token_preview": f"{exchanged_token[:15]}..."
        }
    else:
        return JSONResponse({"error": "Failed to exchange token"}, status_code=500)
