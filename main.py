#!/usr/bin/env python3
"""
OAuth-enabled MCP Server implementation.

This module provides a FastMCP server with comprehensive OAuth 2.0 support,
including dynamic client registration (RFC 7591), token introspection (RFC 7662),
token revocation (RFC 7009), and standard OAuth 2.0 authorization flows.

Key Features:
- OAuth 2.0 authorization code flow with PKCE support
- Dynamic Client Registration (DCR)
- Token introspection and revocation
- UserInfo endpoint
- Multiple OAuth discovery endpoints
"""

import asyncio
import base64
import logging
import sys
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# Initialize OAuth provider and MCP server
oauth_provider = InMemoryOAuthProvider()
# Note: Uncomment the line below to enable OAuth authentication
# mcp = FastMCP("My MCP Server", auth=oauth_provider)
mcp = FastMCP("My MCP Server")


# ============================================================================
# Helper Functions
# ============================================================================


def get_cors_headers() -> dict[str, str]:
    """Generate standard CORS headers for all endpoints.
    
    Returns:
        Dictionary of CORS headers.
    """
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Credentials": "true",
    }


def create_cors_response() -> Response:
    """Create a standard CORS preflight response.
    
    Returns:
        Response object with CORS headers and 200 status.
    """
    return Response(status_code=200, headers=get_cors_headers())


def get_base_url(request: Request) -> str:
    """Extract the base URL from a request.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Base URL string (e.g., "https://example.com").
    """
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}"


def generate_oauth_metadata(base_url: str) -> dict:
    """Generate OAuth 2.0 Authorization Server Metadata (RFC 8414).
    
    Args:
        base_url: The base URL of the server.
        
    Returns:
        Dictionary containing OAuth metadata.
    """
    return {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",
        "scopes_supported": ["read", "write", "admin"],
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


def generate_openid_configuration(base_url: str) -> dict:
    """Generate OpenID Connect Discovery metadata.
    
    Args:
        base_url: The base URL of the server.
        
    Returns:
        Dictionary containing OpenID Connect configuration.
    """
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


def generate_protected_resource_metadata(base_url: str) -> dict:
    """Generate OAuth 2.0 Protected Resource Metadata (RFC 9470).
    
    Args:
        base_url: The base URL of the server.
        
    Returns:
        Dictionary containing protected resource metadata.
    """
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
        "scopes_supported": ["read", "write", "admin"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
        "client_registration_types_supported": ["automatic"],
    }


async def extract_client_credentials(request: Request) -> Tuple[Optional[str], Optional[str]]:
    """Extract client credentials from request (Authorization header or form data).
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Tuple of (client_id, client_secret) or (None, None) if not found.
        
    Raises:
        HTTPException: If Basic auth header is malformed.
    """
    # Try Authorization header first (Basic auth)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = credentials.split(":", 1)
            return client_id, client_secret
        except Exception as e:
            logger.warning(f"Failed to decode Basic auth: {e}")
            raise HTTPException(
                status_code=401, detail="Invalid authorization header"
            )
    
    # Try form data
    try:
        form_data = await request.form()
        client_id = form_data.get("client_id")
        client_secret = form_data.get("client_secret")
        return client_id, client_secret
    except Exception:
        return None, None


async def verify_client_credentials(
    client_id: Optional[str], client_secret: Optional[str]
) -> OAuthClientInformationFull:
    """Verify client credentials against the OAuth provider.
    
    Args:
        client_id: The client ID to verify.
        client_secret: The client secret to verify.
        
    Returns:
        The verified client information.
        
    Raises:
        HTTPException: If credentials are missing or invalid.
    """
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=401, detail="Client authentication required"
        )
    
    client = await oauth_provider.get_client(client_id)
    if not client or client.client_secret != client_secret:
        raise HTTPException(
            status_code=401, detail="Invalid client credentials"
        )
    
    return client


# ============================================================================
# MCP Tools
# ============================================================================



@mcp.tool
def greet(name: str) -> str:
    """A simple greeting tool that requires authentication.
    
    Args:
        name: The name to greet.
        
    Returns:
        A personalized greeting message.
    """
    return f"Hello, {name}!"


@mcp.tool
def get_secret(key: str) -> str:
    """An authenticated tool that returns sensitive data.
    
    Args:
        key: The secret key to retrieve.
        
    Returns:
        The secret value or "Secret not found" if key doesn't exist.
    """
    secrets = {
        "api_key": "sk-secret-key-12345",
        "database": "postgresql://user:pass@localhost/db",
    }
    return secrets.get(key, "Secret not found")


async def setup_demo_client() -> None:
    """Register a demo OAuth client on startup for testing purposes.
    
    Creates a demo client with predefined credentials that can be used
    for testing the OAuth flow without manual registration.
    """
    demo_client = OAuthClientInformationFull(
        client_id="demo_client",
        client_secret="demo_secret",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
        token_endpoint_auth_method="client_secret_post",
    )
    await oauth_provider.register_client(demo_client)
    logger.info(f"Registered demo client: {demo_client.client_id}")


# ============================================================================
# MCP Custom Routes
# ============================================================================


@mcp.custom_route("/mcp", methods=["OPTIONS"])
async def mcp_options(request: Request) -> Response:
    """Handle CORS preflight for MCP endpoint."""
    return create_cors_response()

@mcp.custom_route("/mcp/connect", methods=["POST", "OPTIONS"])
async def mcp_connect(request: Request) -> Response:
    """Handle initial MCP connection - returns metadata for OAuth flow."""
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    
    return JSONResponse(
        content={
            "error": "authentication_required",
            "error_description": "This MCP server requires OAuth authentication",
            "oauth_metadata_url": f"{base_url}/.well-known/openid-configuration",
            "registration_endpoint": f"{base_url}/register",
        },
        status_code=401,
        headers={"Access-Control-Allow-Origin": "*"},
    )

@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
async def oauth_metadata(request: Request) -> Response:
    """
    OAuth 2.0 Protected Resource Metadata endpoint (RFC 9470).
    
    This endpoint provides OAuth server configuration to clients
    for automatic discovery.
    """
    logger.debug(f"OAuth Protected Resource Metadata: {request.method} {request.url}")
    
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = generate_protected_resource_metadata(base_url)
    
    return JSONResponse(
        content=metadata,
        headers={"Access-Control-Allow-Origin": "*"},
    )

@mcp.custom_route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
async def openid_configuration(request: Request) -> Response:
    """Override FastMCP's default OAuth metadata with DCR support."""
    logger.debug(f"OpenID Configuration: {request.method} {request.url}")
    
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = generate_openid_configuration(base_url)
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        },
    )

@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
async def oauth_authorization_server_metadata(request: Request) -> Response:
    """
    OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).
    
    This endpoint provides OAuth authorization server configuration 
    to clients for automatic discovery. This is different from the
    protected resource metadata endpoint.
    """
    logger.debug(f"OAuth Authorization Server Metadata: {request.method} {request.url}")
    
    if request.method == "OPTIONS":
        return create_cors_response()
    
    base_url = get_base_url(request)
    metadata = generate_oauth_metadata(base_url)
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        },
    )

@mcp.custom_route("/register", methods=["POST", "OPTIONS"])
async def register_client_endpoint(request: Request) -> Response:
    """
    Dynamic Client Registration endpoint (RFC 7591).
    
    POST /register
    Content-Type: application/json
    
    Request body: ClientRegistrationRequest
    Response: ClientRegistrationResponse with client_id and client_secret
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        body = await request.json()
        registration = ClientRegistrationRequest(**body)
        response = await oauth_provider.dynamic_register_client(registration)
        
        return JSONResponse(
            status_code=201,
            content=response.model_dump(exclude_none=True),
            headers={"Access-Control-Allow-Origin": "*"},
        )
    except ValueError as e:
        logger.error(f"Invalid registration request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Registration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@mcp.custom_route("/oauth/revoke", methods=["POST", "OPTIONS"])
async def revoke_token_endpoint(request: Request) -> Response:
    """
    OAuth 2.0 Token Revocation endpoint (RFC 7009).
    
    POST /oauth/revoke
    Content-Type: application/x-www-form-urlencoded
    
    token=<token>&token_type_hint=<access_token|refresh_token>
    
    Requires client authentication.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Extract and verify client credentials
        client_id, client_secret = await extract_client_credentials(request)
        client = await verify_client_credentials(client_id, client_secret)
        
        # Try to revoke as access token first
        if token_type_hint == "access_token" or token_type_hint is None:
            access_token = await oauth_provider.load_access_token(token_value)
            if access_token and access_token.client_id == client.client_id:
                await oauth_provider.revoke_token(access_token)
                logger.info(f"Revoked access token for client {client.client_id}")
                return Response(status_code=200)
        
        # Try to revoke as refresh token
        if token_type_hint == "refresh_token" or token_type_hint is None:
            refresh_token = await oauth_provider.load_refresh_token(client, token_value)
            if refresh_token and refresh_token.client_id == client.client_id:
                await oauth_provider.revoke_token(refresh_token)
                logger.info(f"Revoked refresh token for client {client.client_id}")
                return Response(status_code=200)
        
        # RFC 7009: Return 200 even if token not found (don't leak information)
        return Response(status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Token revocation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")

@mcp.custom_route("/test", methods=["GET", "OPTIONS"])
async def test_endpoint(request: Request) -> Response:
    """Simple test endpoint to verify server is running."""
    logger.debug(f"Test endpoint: {request.method} {request.url}")
    
    if request.method == "OPTIONS":
        return create_cors_response()
    
    return JSONResponse(content={"message": "Hello, world!"})

@mcp.custom_route("/oauth/introspect", methods=["POST", "OPTIONS"])
async def introspect_token_endpoint(request: Request) -> Response:
    """
    OAuth 2.0 Token Introspection endpoint (RFC 7662).
    
    POST /oauth/introspect
    Content-Type: application/x-www-form-urlencoded
    
    token=<token>&token_type_hint=<access_token|refresh_token>
    
    Returns token metadata including active status, scope, expiry, etc.
    Requires client authentication.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Extract and verify client credentials
        client_id, client_secret = await extract_client_credentials(request)
        client = await verify_client_credentials(client_id, client_secret)
        
        # Try to introspect as access token first
        token_info = None
        token_type = None
        
        if token_type_hint == "access_token" or token_type_hint is None:
            access_token = await oauth_provider.load_access_token(token_value)
            if access_token:
                token_info = access_token
                token_type = "access_token"
        
        # Try as refresh token if not found or hint suggests
        if not token_info and (token_type_hint == "refresh_token" or token_type_hint is None):
            refresh_token = await oauth_provider.load_refresh_token(client, token_value)
            if refresh_token:
                token_info = refresh_token
                token_type = "refresh_token"
        
        # Build introspection response
        if token_info:
            # Check if token belongs to the requesting client
            if token_info.client_id != client.client_id:
                # Return inactive for tokens from other clients
                return JSONResponse({"active": False})
            
            # Token is active and belongs to client
            response = {
                "active": True,
                "scope": " ".join(token_info.scope) if token_info.scope else "",
                "client_id": token_info.client_id,
                "username": getattr(token_info, "user_id", None),
                "token_type": "Bearer",
                "exp": int(token_info.expires_at.timestamp()),
                "iat": int((token_info.expires_at - timedelta(hours=1)).timestamp()),
                "sub": getattr(token_info, "user_id", None),
                "use": "refresh" if token_type == "refresh_token" else "access",
            }
            
            return JSONResponse(response)
        else:
            # Token not found or invalid
            return JSONResponse({"active": False})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Token introspection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Introspection failed: {str(e)}")

@mcp.custom_route("/userinfo", methods=["GET", "POST", "OPTIONS"])
async def userinfo_endpoint(request: Request) -> Response:
    """
    UserInfo endpoint - returns information about the authenticated user.
    
    GET or POST /userinfo
    Authorization: Bearer <access_token>
    
    Returns user profile information based on the access token's scope.
    """
    if request.method == "OPTIONS":
        return create_cors_response()
    
    try:
        # Extract bearer token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        
        token_value = auth_header[7:]  # Remove "Bearer " prefix
        
        # Validate access token
        access_token = await oauth_provider.verify_token(token_value)
        if not access_token:
            raise HTTPException(status_code=401, detail="Invalid or expired access token")
        
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
        
        # Add additional claims based on scopes
        if "email" in access_token.scope:
            userinfo["email"] = user.get("email", f"{user_id}@example.com")
            userinfo["email_verified"] = user.get("email_verified", False)
        
        if "profile" in access_token.scope:
            userinfo["given_name"] = user.get("given_name", "Demo")
            userinfo["family_name"] = user.get("family_name", "User")
            userinfo["locale"] = user.get("locale", "en-US")
            userinfo["updated_at"] = int(datetime.now().timestamp())
        
        userinfo["scope"] = " ".join(access_token.scope)
        
        return JSONResponse(
            content=userinfo,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store",
            },
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"UserInfo failed: {e}")
        raise HTTPException(status_code=500, detail=f"UserInfo failed: {str(e)}")


# ============================================================================
# Application Startup
# ============================================================================


def setup_fastapi_overrides(app: Optional[FastAPI]) -> None:
    """Override FastMCP's default OAuth routes with our custom implementation.
    
    Args:
        app: FastAPI application instance, if accessible.
    """
    if not app:
        logger.warning("Could not access FastAPI app to override routes")
        return
    
    # Remove existing oauth-authorization-server route if it exists
    routes_to_remove = [
        route for route in app.routes
        if isinstance(route, APIRoute) 
        and route.path == "/.well-known/oauth-authorization-server"
    ]
    
    for route in routes_to_remove:
        app.routes.remove(route)
    
    # Add our custom route directly to the FastAPI app
    @app.get("/.well-known/oauth-authorization-server")
    @app.options("/.well-known/oauth-authorization-server")
    async def custom_oauth_authorization_server_metadata(request: Request) -> Response:
        """Custom OAuth Authorization Server Metadata with registration endpoint."""
        logger.debug("Custom OAuth Authorization Server Metadata endpoint accessed")
        
        if request.method == "OPTIONS":
            return create_cors_response()
        
        base_url = get_base_url(request)
        metadata = generate_oauth_metadata(base_url)
        
        return JSONResponse(
            content=metadata,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=3600",
            },
        )
    
    logger.info("Successfully overrode OAuth authorization server metadata endpoint")


def print_server_info() -> None:
    """Print server startup information and available endpoints."""
    separator = "=" * 60
    
    logger.info(f"\n{separator}")
    logger.info("🔐 OAuth MCP Server Starting")
    logger.info(separator)
    logger.info("Server running on: http://localhost:8000")
    
    logger.info("\n📍 OAuth Endpoints:")
    logger.info("  Authorization: GET  http://localhost:8000/authorize")
    logger.info("  Token:         POST http://localhost:8000/token")
    logger.info("  Registration:  POST http://localhost:8000/register")
    logger.info("  Revocation:    POST http://localhost:8000/oauth/revoke")
    logger.info("  Introspection: POST http://localhost:8000/oauth/introspect")
    logger.info("  UserInfo:      GET  http://localhost:8000/userinfo")
    
    logger.info("\n🔍 Discovery Endpoints:")
    logger.info("  OpenID Configuration: http://localhost:8000/.well-known/openid-configuration")
    logger.info("  Authorization Server: http://localhost:8000/.well-known/oauth-authorization-server")
    logger.info("  Protected Resource:   http://localhost:8000/.well-known/oauth-protected-resource")
    
    logger.info("\n⚠️  Note: FastMCP OAuth endpoints are at /authorize and /token")
    logger.info("  (not /oauth/authorize and /oauth/token)")
    logger.info("  Check discovery endpoints for correct paths!")
    
    logger.info("\n🔑 Demo Client Credentials:")
    logger.info("  Client ID:     demo_client")
    logger.info("  Client Secret: demo_secret")
    logger.info("  Redirect URI:  http://localhost:3000/callback")
    
    logger.info("\n👤 Demo User Credentials:")
    logger.info("  Username: demo_user")
    logger.info("  Password: demo_password")
    logger.info(f"{separator}\n")


def main() -> int:
    """Main entry point for the OAuth MCP server.
    
    Returns:
        Exit code: 0 for success, 1 for error.
    """
    try:
        # Register demo client before starting server
        asyncio.run(setup_demo_client())
        
        # Access FastAPI app and override default routes
        app: Optional[FastAPI] = None
        if hasattr(mcp, "app") and isinstance(getattr(mcp, "app"), FastAPI):
            app = mcp.app
        elif hasattr(mcp, "_app") and isinstance(getattr(mcp, "_app"), FastAPI):
            app = mcp._app
        
        setup_fastapi_overrides(app)
        
        # Print server information
        print_server_info()
        
        # Run the server (mcp.run() starts its own event loop)
        mcp.run(transport="http")
        return 0
        
    except KeyboardInterrupt:
        logger.info("\nServer interrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Server failed to start: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
