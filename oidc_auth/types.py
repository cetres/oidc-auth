"""
OIDC Types and Configuration

This module defines Pydantic models for OIDC configuration, leveraging BaseSettings
to load values from environment variables or provide sensible defaults.

It also includes type definitions for session data.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, Literal

class OIDCSettings(BaseSettings):
    """
    Pydantic model for OpenID Connect (OIDC) configuration settings.

    Settings are loaded from environment variables (prefixed with 'OIDC_')
    or defaults specified here.
    """
    model_config = SettingsConfigDict(env_prefix='OIDC_', extra='ignore')

    CLIENT_ID: str = Field(..., description="The OIDC client ID provided by the IdP.")
    CLIENT_SECRET: str = Field(..., description="The OIDC client secret provided by the IdP.")
    ISSUER_URL: str = Field(..., description="The OIDC issuer URL (e.g., 'https://accounts.google.com').")
    AUTHORIZE_URL: str = Field(..., description="The OIDC authorization endpoint URL.")
    TOKEN_URL: str = Field(..., description="The OIDC token endpoint URL.")
    USERINFO_URL: str = Field(..., description="The OIDC user info endpoint URL.")
    REDIRECT_URI: str = Field("http://localhost:8000/oidc/callback", description="The callback URL registered with the IdP.")
    SCOPE: str = Field("openid email profile", description="The OIDC scopes requested during authorization.")
    COOKIE_SECURE: bool = Field(False, description="Whether the session cookie should be marked as 'Secure'. Set to True for HTTPS environments.")
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = Field("lax", description="The SameSite attribute for the session cookie.")


# Example of session data type
SessionData = Dict[str, Any]
