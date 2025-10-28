from fastmcp import FastMCP
from oauth_provider import InMemoryOAuthProvider, ClientRegistrationRequest, ClientRegistrationResponse
from mcp.shared.auth import OAuthClientInformationFull
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, Response

# Create MCP server with OAuth authentication
oauth_provider = InMemoryOAuthProvider()
# mcp = FastMCP("My MCP Server", auth=oauth_provider)
mcp = FastMCP("My MCP Server")

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

# Add CORS handler for SSE endpoint
@mcp.custom_route("/sse", methods=["OPTIONS"])
async def sse_options(request: Request):
    """Handle CORS preflight for SSE endpoint."""
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
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
    
    base_url = "http://localhost:8000"
    
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
    }
    
    return JSONResponse(
        content=metadata,
        headers={
            "Access-Control-Allow-Origin": "*",
        }
    )

# Add DCR endpoint to the FastAPI app
@mcp.custom_route("/oauth/register", methods=["POST", "OPTIONS"])
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

if __name__ == "__main__":
    import asyncio
    
    # Register demo client before starting server
    asyncio.run(setup_demo_client())
    
    print("\n" + "="*60)
    print("🔐 OAuth MCP Server Starting")
    print("="*60)
    print(f"Server running on: http://localhost:8000")
    print(f"\nDynamic Client Registration (DCR):")
    print(f"  POST http://localhost:8000/oauth/register")
    print(f"  Content-Type: application/json")
    print(f"\nDemo Client Credentials:")
    print(f"  Client ID: demo_client")
    print(f"  Client Secret: demo_secret")
    print(f"  Redirect URI: http://localhost:3000/callback")
    print(f"\nDemo User Credentials:")
    print(f"  Username: demo_user")
    print(f"  Password: demo_password")
    print("="*60 + "\n")
    
    # Run the server (mcp.run() starts its own event loop)
    mcp.run(transport='sse')