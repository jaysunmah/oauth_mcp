"""
OAuth 2.0 MCP Server with FastMCP

This module implements a complete OAuth 2.0/2.1 authorization server with MCP (Model Context Protocol)
integration. It provides:
- OAuth 2.0 Authorization Code flow with PKCE
- Dynamic Client Registration (RFC 7591)
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
- OpenID Connect UserInfo endpoint
- Multiple OAuth discovery endpoints

Copyright Anysphere Inc.
"""

import asyncio
import base64
from datetime import datetime, timedelta
from typing import Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull

from oauth_provider import (
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    InMemoryOAuthProvider,
)

# ============================================================================
# Configuration
# ============================================================================

SERVER_NAME = "My MCP Server"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
BASE_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

# OAuth Scopes
SUPPORTED_SCOPES = ["read", "write", "admin", "email", "profile"]

# CORS Headers
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "*",
}

# Demo Credentials
DEMO_CLIENT_ID = "demo_client"
DEMO_CLIENT_SECRET = "demo_secret"
DEMO_REDIRECT_URI = "http://localhost:3000/callback"
DEMO_USERNAME = "demo_user"
DEMO_PASSWORD = "demo_password"

# ============================================================================
# Global Instances
# ============================================================================

oauth_provider = InMemoryOAuthProvider()
mcp = FastMCP(SERVER_NAME)

# ============================================================================
# Helper Functions
# ============================================================================


def get_base_url(request: Request) -> str:
    """Extract base URL from request headers."""
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}"


def create_cors_response(
    status_code: int = 200,
    methods: str = "GET, POST, OPTIONS",
    allow_credentials: bool = False,
) -> Response:
    """Create a CORS preflight response."""
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": methods,
        "Access-Control-Allow-Headers": "*",
    }
    if allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"
    return Response(status_code=status_code, headers=headers)


def create_json_response(
    content: dict,
    status_code: int = 200,
    cache_control: Optional[str] = None,
) -> JSONResponse:
    """Create a JSON response with CORS headers."""
    headers = CORS_HEADERS.copy()
    if cache_control:
        headers["Cache-Control"] = cache_control
    return JSONResponse(content=content, status_code=status_code, headers=headers)


async def extract_client_credentials(
    request: Request,
    form_data: Optional[dict] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract client credentials from request.
    
    Supports both Basic Authentication and form parameters.
    Returns (client_id, client_secret) tuple.
    """
    auth_header = request.headers.get("Authorization", "")
    
    # Try Basic Authentication first
    if auth_header.startswith("Basic "):
        try:
            credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = credentials.split(":", 1)
            return client_id, client_secret
        except Exception:
            raise HTTPException(
                status_code=401, detail="Invalid authorization header"
            )
    
    # Fall back to form parameters
    if form_data:
        client_id = form_data.get("client_id")
        client_secret = form_data.get("client_secret")
        return client_id, client_secret
    
    return None, None


def build_oauth_metadata(base_url: str) -> dict:
    """Build OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    return {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",
        "scopes_supported": SUPPORTED_SCOPES,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": f"{base_url}/docs",
        "registration_endpoint_auth_methods_supported": ["none"],
        "client_registration_types_supported": ["automatic"],
    }


def build_openid_configuration(base_url: str) -> dict:
    """Build OpenID Connect Discovery metadata."""
    return {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "service_documentation": f"{base_url}/docs",
        "code_challenge_methods_supported": ["S256"],
        "registration_endpoint_auth_methods_supported": ["none"],
        "client_registration_types_supported": ["automatic"],
    }


def build_protected_resource_metadata(base_url: str) -> dict:
    """Build OAuth 2.0 Protected Resource Metadata (RFC 9470)."""
    return {
        "resource": base_url,
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": [],
        "resource_encryption_alg_values_supported": [],
        "resource_encryption_enc_values_supported": [],
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "scopes_supported": SUPPORTED_SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
        "client_registration_types_supported": ["automatic"],
    }


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool
def greet(name: str) -> str:
    """A simple greeting tool that requires authentication."""
    return f"Hello, {name}!"


@mcp.tool
def get_secret(key: str) -> str:
    """An authenticated tool that returns sensitive data."""
    secrets = {
        "api_key": "sk-secret-key-12345",
        "database": "postgresql://user:pass@localhost/db",
    }
    return secrets.get(key, "Secret not found")


# ============================================================================
# Discovery Endpoints
# ============================================================================


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
async def oauth_authorization_server_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).
    
    Provides OAuth authorization server configuration to clients for
    automatic discovery. This is the primary discovery endpoint.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = build_oauth_metadata(base_url)
    return create_json_response(metadata, cache_control="public, max-age=3600")


@mcp.custom_route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
async def openid_configuration(request: Request):
    """OpenID Connect Discovery endpoint."""
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = build_openid_configuration(base_url)
    return create_json_response(metadata, cache_control="public, max-age=3600")


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
async def oauth_protected_resource_metadata(request: Request):
    """OAuth 2.0 Protected Resource Metadata endpoint (RFC 9470)."""
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = build_protected_resource_metadata(base_url)
    return create_json_response(metadata)


# ============================================================================
# Client Registration Endpoint
# ============================================================================


@mcp.custom_route("/register", methods=["POST", "OPTIONS"])
async def register_client_endpoint(request: Request):
    """
    Dynamic Client Registration endpoint (RFC 7591).
    
    Allows clients to register themselves dynamically at runtime.
    Returns client_id and client_secret in the response.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        body = await request.json()
        registration = ClientRegistrationRequest(**body)
        response = await oauth_provider.dynamic_register_client(registration)
        
        return create_json_response(
            response.model_dump(exclude_none=True),
            status_code=201,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


# ============================================================================
# Token Management Endpoints
# ============================================================================


@mcp.custom_route("/oauth/revoke", methods=["POST", "OPTIONS"])
async def revoke_token_endpoint(request: Request):
    """
    OAuth 2.0 Token Revocation endpoint (RFC 7009).
    
    Revokes access tokens or refresh tokens. Returns 200 OK even if the
    token doesn't exist to prevent information leakage.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Authenticate client
        client_id, client_secret = await extract_client_credentials(
            request, dict(form_data)
        )
        
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=401, detail="Client authentication required"
            )
        
        client = await oauth_provider.get_client(client_id)
        if not client or client.client_secret != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Try to revoke as access token
        if token_type_hint == "access_token" or token_type_hint is None:
            access_token = await oauth_provider.load_access_token(token_value)
            if access_token and access_token.client_id == client_id:
                await oauth_provider.revoke_token(access_token)
                return Response(status_code=200)
        
        # Try to revoke as refresh token
        if token_type_hint == "refresh_token" or token_type_hint is None:
            refresh_token = await oauth_provider.load_refresh_token(client, token_value)
            if refresh_token and refresh_token.client_id == client_id:
                await oauth_provider.revoke_token(refresh_token)
                return Response(status_code=200)
        
        # RFC 7009: Return 200 even if token not found
        return Response(status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")


@mcp.custom_route("/oauth/introspect", methods=["POST", "OPTIONS"])
async def introspect_token_endpoint(request: Request):
    """
    OAuth 2.0 Token Introspection endpoint (RFC 7662).
    
    Returns metadata about a token including active status, scope, expiry, etc.
    Clients can only introspect their own tokens.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Authenticate client
        client_id, client_secret = await extract_client_credentials(
            request, dict(form_data)
        )
        
        if not client_id or not client_secret:
            raise HTTPException(
                status_code=401, detail="Client authentication required"
            )
        
        client = await oauth_provider.get_client(client_id)
        if not client or client.client_secret != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Try to find the token
        token_info = None
        token_type = None
        
        if token_type_hint == "access_token" or token_type_hint is None:
            access_token = await oauth_provider.load_access_token(token_value)
            if access_token:
                token_info = access_token
                token_type = "access_token"
        
        if not token_info and (
            token_type_hint == "refresh_token" or token_type_hint is None
        ):
            refresh_token = await oauth_provider.load_refresh_token(client, token_value)
            if refresh_token:
                token_info = refresh_token
                token_type = "refresh_token"
        
        # Build introspection response
        if token_info:
            # Verify token belongs to requesting client
            if token_info.client_id != client_id:
                return create_json_response({"active": False})
            
            response = {
                "active": True,
                "scope": " ".join(token_info.scope) if token_info.scope else "",
                "client_id": token_info.client_id,
                "username": getattr(token_info, "user_id", None),
                "token_type": "Bearer",
                "exp": int(token_info.expires_at.timestamp()),
                "iat": int(
                    (token_info.expires_at - timedelta(hours=1)).timestamp()
                ),
                "sub": getattr(token_info, "user_id", None),
                "use": "refresh" if token_type == "refresh_token" else "access",
            }
            return create_json_response(response)
        else:
            return create_json_response({"active": False})
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Introspection failed: {str(e)}"
        )


# ============================================================================
# UserInfo Endpoint
# ============================================================================


@mcp.custom_route("/userinfo", methods=["GET", "POST", "OPTIONS"])
async def userinfo_endpoint(request: Request):
    """
    OpenID Connect UserInfo endpoint.
    
    Returns user profile information based on the provided access token
    and its associated scopes.
    """
    if request.method == "OPTIONS":
        return create_cors_response(methods="GET, POST, OPTIONS")
    
    try:
        # Extract and validate bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        
        token_value = auth_header[7:]
        access_token = await oauth_provider.verify_token(token_value)
        
        if not access_token:
            raise HTTPException(
                status_code=401, detail="Invalid or expired access token"
            )
        
        # Get user information
        user_id = getattr(access_token, "user_id", None)
        if not user_id:
            raise HTTPException(status_code=500, detail="User ID not found in token")
        
        user = oauth_provider.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build userinfo response based on scopes
        userinfo = {
            "sub": user_id,
            "name": user.get("username", user_id),
            "preferred_username": user.get("username", user_id),
        }
        
        if "email" in access_token.scope:
            userinfo["email"] = user.get("email", f"{user_id}@example.com")
            userinfo["email_verified"] = user.get("email_verified", False)
        
        if "profile" in access_token.scope:
            userinfo["given_name"] = user.get("given_name", "Demo")
            userinfo["family_name"] = user.get("family_name", "User")
            userinfo["locale"] = user.get("locale", "en-US")
            userinfo["updated_at"] = int(datetime.now().timestamp())
        
        userinfo["scope"] = " ".join(access_token.scope)
        
        return create_json_response(userinfo, cache_control="no-store")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"UserInfo failed: {str(e)}")


# ============================================================================
# MCP Connection Endpoints
# ============================================================================


@mcp.custom_route("/mcp", methods=["OPTIONS"])
async def mcp_options(request: Request):
    """Handle CORS preflight for MCP endpoint."""
    return create_cors_response(allow_credentials=True)


@mcp.custom_route("/mcp/connect", methods=["POST", "OPTIONS"])
async def mcp_connect(request: Request):
    """
    Handle initial MCP connection.
    
    Returns metadata for OAuth flow when authentication is required.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    
    return create_json_response(
        {
            "error": "authentication_required",
            "error_description": "This MCP server requires OAuth authentication",
            "oauth_metadata_url": f"{base_url}/.well-known/openid-configuration",
            "registration_endpoint": f"{base_url}/register",
        },
        status_code=401,
    )


@mcp.custom_route("/test", methods=["GET", "OPTIONS"])
async def test_endpoint(request: Request):
    """Simple test endpoint for health checks."""
    if request.method == "OPTIONS":
        return create_cors_response()
    return create_json_response({"message": "Hello, world!"})


# ============================================================================
# Initialization
# ============================================================================


async def setup_demo_client():
    """Register a demo OAuth client on startup."""
    demo_client = OAuthClientInformationFull(
        client_id=DEMO_CLIENT_ID,
        client_secret=DEMO_CLIENT_SECRET,
        redirect_uris=[DEMO_REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
        token_endpoint_auth_method="client_secret_post",
    )
    await oauth_provider.register_client(demo_client)
    print(f"✅ Registered demo client: {demo_client.client_id}")


def override_fastmcp_routes(app: FastAPI):
    """
    Override FastMCP's default OAuth routes.
    
    FastMCP creates default OAuth routes that don't include DCR support.
    This function removes those routes and ensures our custom routes are used.
    """
    routes_to_remove = []
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == "/.well-known/oauth-authorization-server":
            routes_to_remove.append(route)
    
    for route in routes_to_remove:
        app.routes.remove(route)
    
    # Add custom route handler
    @app.get("/.well-known/oauth-authorization-server")
    @app.options("/.well-known/oauth-authorization-server")
    async def custom_oauth_authorization_server_metadata(request: Request):
        """Custom OAuth Authorization Server Metadata with DCR support."""
        if request.method == "OPTIONS":
            return create_cors_response()
        
        base_url = get_base_url(request)
        metadata = build_oauth_metadata(base_url)
        return create_json_response(metadata, cache_control="public, max-age=3600")


def print_startup_banner():
    """Print server startup information."""
    print("\n" + "=" * 60)
    print("🔐 OAuth MCP Server Starting")
    print("=" * 60)
    print(f"Server running on: http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    
    print("\n📍 OAuth Endpoints:")
    print(f"  Authorization: GET  http://{DEFAULT_HOST}:{DEFAULT_PORT}/authorize")
    print(f"  Token:         POST http://{DEFAULT_HOST}:{DEFAULT_PORT}/token")
    print(f"  Registration:  POST http://{DEFAULT_HOST}:{DEFAULT_PORT}/register")
    print(f"  Revocation:    POST http://{DEFAULT_HOST}:{DEFAULT_PORT}/oauth/revoke")
    print(f"  Introspection: POST http://{DEFAULT_HOST}:{DEFAULT_PORT}/oauth/introspect")
    print(f"  UserInfo:      GET  http://{DEFAULT_HOST}:{DEFAULT_PORT}/userinfo")
    
    print("\n🔍 Discovery Endpoints:")
    print(f"  OpenID Configuration: http://{DEFAULT_HOST}:{DEFAULT_PORT}/.well-known/openid-configuration")
    print(f"  Authorization Server: http://{DEFAULT_HOST}:{DEFAULT_PORT}/.well-known/oauth-authorization-server")
    print(f"  Protected Resource:   http://{DEFAULT_HOST}:{DEFAULT_PORT}/.well-known/oauth-protected-resource")
    
    print(f"\n⚠️  Important: If using FastMCP's default OAuth, endpoints are at:")
    print(f"  /authorize, /token (not /oauth/authorize, /oauth/token)")
    print(f"  Check the discovery endpoints above for the correct paths!")
    
    print(f"\n🔑 Demo Client Credentials:")
    print(f"  Client ID:     {DEMO_CLIENT_ID}")
    print(f"  Client Secret: {DEMO_CLIENT_SECRET}")
    print(f"  Redirect URI:  {DEMO_REDIRECT_URI}")
    
    print(f"\n👤 Demo User Credentials:")
    print(f"  Username: {DEMO_USERNAME}")
    print(f"  Password: {DEMO_PASSWORD}")
    print("=" * 60 + "\n")


# ============================================================================
# Main Entry Point
# ============================================================================


if __name__ == "__main__":
    # Register demo client
    asyncio.run(setup_demo_client())
    
    # Try to override FastMCP's default routes
    app = None
    if hasattr(mcp, "app") and isinstance(getattr(mcp, "app"), FastAPI):
        app = mcp.app
    elif hasattr(mcp, "_app") and isinstance(getattr(mcp, "_app"), FastAPI):
        app = mcp._app
    
    if app:
        override_fastmcp_routes(app)
        print("✅ Successfully overrode OAuth authorization server metadata endpoint")
    else:
        print("⚠️  Could not access FastAPI app to override routes")
    
    # Print startup information
    print_startup_banner()
    
    # Run the server
    mcp.run(transport="http")
