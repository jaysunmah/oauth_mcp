from fastmcp import FastMCP
from oauth_provider import InMemoryOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull

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

if __name__ == "__main__":
    import asyncio
    
    # Register demo client before starting server
    asyncio.run(setup_demo_client())
    
    print("\n" + "="*60)
    print("🔐 OAuth MCP Server Starting")
    print("="*60)
    print(f"Server running on: http://localhost:8000")
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