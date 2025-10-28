from fastmcp import FastMCP
from oauth_provider import InMemoryOAuthProvider, ClientRegistrationRequest, ClientRegistrationResponse
from mcp.shared.auth import OAuthClientInformationFull
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, Response
from datetime import timedelta, datetime

# Create MCP server with OAuth authentication
oauth_provider = InMemoryOAuthProvider()
mcp = FastMCP("My MCP Server", auth=oauth_provider)

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

async def setup_demo_client():
    """Register a demo OAuth client on startup."""
    demo_client = OAuthClientInformationFull(
        client_id="demo_client",
        client_secret="demo_secret",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",  # Space-separated string
        token_endpoint_auth_method="client_secret_post",
    )
    await oauth_provider.register_client(demo_client)
    print(f"✅ Registered demo client: {demo_client.client_id}")

# Add CORS handler for MCP endpoint
@mcp.custom_route("/mcp", methods=["OPTIONS"])
async def mcp_options(request: Request):
    """Handle CORS preflight for MCP endpoint."""
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# Add handler for initial connection without auth
@mcp.custom_route("/mcp/connect", methods=["POST", "OPTIONS"])
async def mcp_connect(request: Request):
    """Handle initial MCP connection - returns metadata for OAuth flow."""
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    # Return information about how to authenticate
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    base_url = f"{scheme}://{host}"
    
    return JSONResponse(
        content={
            "error": "authentication_required",
            "error_description": "This MCP server requires OAuth authentication",
            "oauth_metadata_url": f"{base_url}/.well-known/openid-configuration",
            "registration_endpoint": f"{base_url}/register",
        },
        status_code=401,
        headers={
            "Access-Control-Allow-Origin": "*",
        }
    )

# Add OAuth metadata endpoint
@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Protected Resource Metadata endpoint (RFC 9470).
    
    This endpoint provides OAuth server configuration to clients
    for automatic discovery.
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    # Dynamically determine base URL from request
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    base_url = f"{scheme}://{host}"
    
    metadata = {
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
            "client_secret_post"
        ],
        "code_challenge_methods_supported": ["S256"],
        # Ensure DCR support is visible
        "client_registration_types_supported": ["automatic"],
    }
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
        }
    )

# Override the default OAuth metadata endpoint that FastMCP creates
@mcp.custom_route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
async def openid_configuration(request: Request):
    """Override FastMCP's default OAuth metadata with DCR support."""
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    # Get the base URL dynamically
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    base_url = f"{scheme}://{host}"
    
    # Return metadata with DCR support
    metadata = {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",  # THIS IS THE KEY FIELD
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "service_documentation": f"{base_url}/docs",
        "code_challenge_methods_supported": ["S256"],
        "registration_endpoint_auth_methods_supported": ["none"],
        "client_registration_types_supported": ["automatic"],
    }
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        }
    )

# Also keep the standard OAuth Authorization Server Metadata endpoint
@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
async def oauth_authorization_server_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).
    
    This endpoint provides OAuth authorization server configuration 
    to clients for automatic discovery. This is different from the
    protected resource metadata endpoint.
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    # Dynamically determine base URL from request
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    base_url = f"{scheme}://{host}"
    
    # RFC 8414 compliant metadata - INCLUDING registration_endpoint!
    metadata = {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",  # CRITICAL FOR DCR SUPPORT
        "scopes_supported": ["read", "write", "admin"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],  # For future OIDC support
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": f"{base_url}/docs",
        # DCR support fields - REQUIRED for dynamic client registration
        "registration_endpoint_auth_methods_supported": ["none"],
        "client_registration_types_supported": ["automatic"]
    }
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
        }
    )

# Add DCR endpoint at the root level where FastMCP expects it
@mcp.custom_route("/register", methods=["POST", "OPTIONS"])
async def register_client_endpoint(request: Request):
    """
    Dynamic Client Registration endpoint (RFC 7591).
    
    POST /oauth/register
    Content-Type: application/json
    
    Request body: ClientRegistrationRequest
    Response: ClientRegistrationResponse with client_id and client_secret
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    try:
        # Parse request body
        body = await request.json()
        registration = ClientRegistrationRequest(**body)
        
        # Register the client
        response = await oauth_provider.dynamic_register_client(registration)
        
        # Return registration response
        return JSONResponse(
            status_code=201,
            content=response.model_dump(exclude_none=True),
            headers={
                "Access-Control-Allow-Origin": "*",
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

# Add Token Revocation endpoint
@mcp.custom_route("/oauth/revoke", methods=["POST", "OPTIONS"])
async def revoke_token_endpoint(request: Request):
    """
    OAuth 2.0 Token Revocation endpoint (RFC 7009).
    
    POST /oauth/revoke
    Content-Type: application/x-www-form-urlencoded
    
    token=<token>&token_type_hint=<access_token|refresh_token>
    
    Requires client authentication.
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    try:
        # Parse form data
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Extract client credentials from Authorization header or form data
        auth_header = request.headers.get("Authorization", "")
        client_id = None
        client_secret = None
        
        if auth_header.startswith("Basic "):
            # Decode Basic auth
            import base64
            try:
                credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                client_id, client_secret = credentials.split(":", 1)
            except:
                raise HTTPException(status_code=401, detail="Invalid authorization header")
        else:
            # Try form data
            client_id = form_data.get("client_id")
            client_secret = form_data.get("client_secret")
        
        if not client_id or not client_secret:
            raise HTTPException(status_code=401, detail="Client authentication required")
        
        # Verify client credentials
        client = await oauth_provider.get_client(client_id)
        if not client or client.client_secret != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
        # Try to revoke as access token first
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
        
        # RFC 7009: Return 200 even if token not found (don't leak information)
        return Response(status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")

# Add Token Introspection endpoint
@mcp.custom_route("/oauth/introspect", methods=["POST", "OPTIONS"])
async def introspect_token_endpoint(request: Request):
    """
    OAuth 2.0 Token Introspection endpoint (RFC 7662).
    
    POST /oauth/introspect
    Content-Type: application/x-www-form-urlencoded
    
    token=<token>&token_type_hint=<access_token|refresh_token>
    
    Returns token metadata including active status, scope, expiry, etc.
    Requires client authentication.
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    try:
        # Parse form data
        form_data = await request.form()
        token_value = form_data.get("token")
        token_type_hint = form_data.get("token_type_hint", "access_token")
        
        if not token_value:
            raise HTTPException(status_code=400, detail="Missing token parameter")
        
        # Extract client credentials (same as revocation)
        auth_header = request.headers.get("Authorization", "")
        client_id = None
        client_secret = None
        
        if auth_header.startswith("Basic "):
            import base64
            try:
                credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                client_id, client_secret = credentials.split(":", 1)
            except:
                raise HTTPException(status_code=401, detail="Invalid authorization header")
        else:
            client_id = form_data.get("client_id")
            client_secret = form_data.get("client_secret")
        
        if not client_id or not client_secret:
            raise HTTPException(status_code=401, detail="Client authentication required")
        
        # Verify client credentials
        client = await oauth_provider.get_client(client_id)
        if not client or client.client_secret != client_secret:
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        
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
            # (clients can only introspect their own tokens in this implementation)
            if token_info.client_id != client_id:
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
                "iat": int((token_info.expires_at - timedelta(hours=1)).timestamp()),  # Approximate issued at
                "sub": getattr(token_info, "user_id", None),  # Subject
            }
            
            # Add token-type specific fields
            if token_type == "refresh_token":
                response["use"] = "refresh"
            else:
                response["use"] = "access"
            
            return JSONResponse(response)
        else:
            # Token not found or invalid
            return JSONResponse({"active": False})
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Introspection failed: {str(e)}")

# Add UserInfo endpoint
@mcp.custom_route("/userinfo", methods=["GET", "POST", "OPTIONS"])
async def userinfo_endpoint(request: Request):
    """
    UserInfo endpoint - returns information about the authenticated user.
    
    GET or POST /userinfo
    Authorization: Bearer <access_token>
    
    Returns user profile information based on the access token's scope.
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
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
        
        # Get user information based on the token
        user_id = getattr(access_token, "user_id", None)
        if not user_id:
            raise HTTPException(status_code=500, detail="User ID not found in token")
        
        # Get user from provider's user database
        user = oauth_provider.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build userinfo response based on scopes
        userinfo = {
            "sub": user_id,  # Subject identifier
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
        
        # Include granted scopes
        userinfo["scope"] = " ".join(access_token.scope)
        
        return JSONResponse(
            content=userinfo,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store",  # Don't cache user info
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"UserInfo failed: {str(e)}")

if __name__ == "__main__":
    import asyncio
    
    # Register demo client before starting server
    asyncio.run(setup_demo_client())
    
    # Important: Override FastMCP's default OAuth routes
    # FastMCP creates these routes when auth is provided, so we override them
    print("\n🔧 Overriding FastMCP's default OAuth routes...")
    
    print("\n" + "="*60)
    print("🔐 OAuth MCP Server Starting")
    print("="*60)
    print(f"Server running on: http://localhost:8000")
    
    print(f"\n📍 OAuth Endpoints:")
    print(f"  Authorization: GET  http://localhost:8000/authorize")
    print(f"  Token:         POST http://localhost:8000/token")
    print(f"  Registration:  POST http://localhost:8000/register")
    print(f"  Revocation:    POST http://localhost:8000/oauth/revoke")
    print(f"  Introspection: POST http://localhost:8000/oauth/introspect")
    print(f"  UserInfo:      GET  http://localhost:8000/userinfo")
    
    print(f"\n🔍 Discovery Endpoints:")
    print(f"  OpenID Configuration: http://localhost:8000/.well-known/openid-configuration")
    print(f"  Authorization Server: http://localhost:8000/.well-known/oauth-authorization-server")
    print(f"  Protected Resource:   http://localhost:8000/.well-known/oauth-protected-resource")
    
    print(f"\n⚠️  Important: If using FastMCP's default OAuth, endpoints are at:")
    print(f"  /authorize, /token (not /oauth/authorize, /oauth/token)")
    print(f"  Check the discovery endpoints above for the correct paths!")
    
    print(f"\n🔑 Demo Client Credentials:")
    print(f"  Client ID:     demo_client")
    print(f"  Client Secret: demo_secret")
    print(f"  Redirect URI:  http://localhost:3000/callback")
    
    print(f"\n👤 Demo User Credentials:")
    print(f"  Username: demo_user")
    print(f"  Password: demo_password")
    print("="*60 + "\n")
    
    # Run the server (mcp.run() starts its own event loop)
    mcp.run(transport='http')