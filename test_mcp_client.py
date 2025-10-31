#!/usr/bin/env python3
"""
Test MCP Client with OAuth Authentication

This script tests the MCP server with OAuth authentication flow.
It demonstrates:
1. Dynamic client registration (optional)
2. OAuth authorization flow
3. Calling MCP tools with authentication
4. Token refresh
"""

import asyncio
import json
import hashlib
import base64
import secrets
from urllib.parse import urlencode, parse_qs, urlparse
import httpx
from typing import Optional, Dict, Any
import sys


class OAuthMCPClient:
    """MCP Client with OAuth 2.1 support."""
    
    def __init__(
        self,
        server_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: str = "http://localhost:9999/callback",
    ):
        self.server_url = server_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.mcp_session_url: Optional[str] = None
    
    async def discover_oauth_metadata(self):
        """Discover OAuth server metadata."""
        print("\n🔍 Discovering OAuth server metadata...")
        
        async with httpx.AsyncClient() as client:
            # Try different discovery endpoints
            endpoints = [
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/oauth-protected-resource"
            ]
            
            for endpoint in endpoints:
                try:
                    response = await client.get(f"{self.server_url}{endpoint}")
                    if response.status_code == 200:
                        metadata = response.json()
                        print(f"   ✅ Found metadata at {endpoint}")
                        print(f"   Authorization: {metadata.get('authorization_endpoint', 'N/A')}")
                        print(f"   Token: {metadata.get('token_endpoint', 'N/A')}")
                        print(f"   Registration: {metadata.get('registration_endpoint', 'N/A')}")
                        return metadata
                except:
                    pass
            
            print("   ⚠️  Could not discover OAuth metadata")
            return None
    
    async def register_client_dynamically(self) -> bool:
        """Register a new OAuth client dynamically."""
        print("\n📝 Registering new OAuth client...")
        
        async with httpx.AsyncClient() as client:
            registration_data = {
                "redirect_uris": [self.redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "client_name": "Test MCP Client",
                "token_endpoint_auth_method": "client_secret_post"
            }
            
            try:
                response = await client.post(
                    f"{self.server_url}/register",
                    json=registration_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in (200, 201):
                    reg_response = response.json()
                    self.client_id = reg_response["client_id"]
                    self.client_secret = reg_response["client_secret"]
                    
                    print(f"   ✅ Registered successfully!")
                    print(f"   Client ID: {self.client_id}")
                    print(f"   Client Secret: {self.client_secret[:20]}...")
                    return True
                else:
                    print(f"   ❌ Registration failed: {response.status_code}")
                    print(f"   Response: {response.text}")
                    return False
                    
            except Exception as e:
                print(f"   ❌ Registration error: {str(e)}")
                return False
    
    def generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(
            challenge_bytes
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(
        self,
        code_challenge: str,
        scope: list[str] = None,
        state: str = None,
    ) -> str:
        """Build authorization URL."""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        if scope:
            params['scope'] = ' '.join(scope)
        
        if state:
            params['state'] = state
        
        return f"{self.server_url}/authorize?{urlencode(params)}"
    
    async def simulate_authorization(self, auth_url: str) -> tuple[str, str]:
        """Simulate authorization flow (for testing)."""
        print("\n🔐 Simulating authorization flow...")
        print(f"   Auth URL: {auth_url}")
        
        async with httpx.AsyncClient(follow_redirects=False) as client:
            # The demo server auto-approves, so we just need to follow the redirect
            response = await client.get(auth_url)
            
            if response.status_code in (302, 303, 307, 308):
                redirect_location = response.headers.get('Location', '')
                parsed = urlparse(redirect_location)
                query_params = parse_qs(parsed.query)
                
                if 'code' in query_params:
                    code = query_params['code'][0]
                    state = query_params.get('state', [None])[0]
                    print(f"   ✅ Got authorization code: {code[:20]}...")
                    return code, state
                else:
                    print(f"   ❌ No code in redirect: {redirect_location}")
                    return None, None
            else:
                print(f"   ❌ Unexpected response: {response.status_code}")
                print(f"   Body: {response.text}")
                return None, None
    
    async def exchange_code_for_token(
        self,
        authorization_code: str,
        code_verifier: str,
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        print("\n🔄 Exchanging code for token...")
        
        async with httpx.AsyncClient() as client:
            token_data = {
                'grant_type': 'authorization_code',
                'code': authorization_code,
                'redirect_uri': self.redirect_uri,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code_verifier': code_verifier,
            }
            
            response = await client.post(
                f"{self.server_url}/token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                token_response = response.json()
                self.access_token = token_response['access_token']
                self.refresh_token = token_response.get('refresh_token')
                
                print(f"   ✅ Got access token: {self.access_token[:20]}...")
                if self.refresh_token:
                    print(f"   ✅ Got refresh token: {self.refresh_token[:20]}...")
                
                return token_response
            else:
                print(f"   ❌ Token exchange failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
    
    async def initialize_mcp_session(self) -> bool:
        """Initialize MCP session with OAuth token."""
        print("\n🚀 Initializing MCP session...")
        
        if not self.access_token:
            print("   ❌ No access token available")
            return False
        
        async with httpx.AsyncClient() as client:
            # Try to connect to the MCP SSE endpoint with auth
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'text/event-stream',
            }
            
            try:
                # First, try to get server info
                response = await client.post(
                    f"{self.server_url}/mcp",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {}
                        },
                        "id": 1
                    }
                )
                
                if response.status_code == 200:
                    print("   ✅ MCP session initialized successfully")
                    return True
                else:
                    print(f"   ❌ MCP initialization failed: {response.status_code}")
                    print(f"   Response: {response.text}")
                    return False
                    
            except Exception as e:
                print(f"   ❌ MCP connection error: {str(e)}")
                return False
    
    async def list_tools(self) -> list:
        """List available MCP tools."""
        print("\n🔧 Listing available tools...")
        
        if not self.access_token:
            print("   ❌ Not authenticated")
            return []
        
        async with httpx.AsyncClient() as client:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
            }
            
            response = await client.post(
                f"{self.server_url}/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                    "id": 2
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'result' in result and 'tools' in result['result']:
                    tools = result['result']['tools']
                    for tool in tools:
                        print(f"   📦 {tool['name']}: {tool.get('description', 'No description')}")
                    return tools
                else:
                    print(f"   ⚠️  Unexpected response format")
                    return []
            else:
                print(f"   ❌ Failed to list tools: {response.status_code}")
                return []
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call an MCP tool."""
        print(f"\n📞 Calling tool: {tool_name}")
        print(f"   Arguments: {arguments}")
        
        if not self.access_token:
            print("   ❌ Not authenticated")
            return None
        
        async with httpx.AsyncClient() as client:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
            }
            
            response = await client.post(
                f"{self.server_url}/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments
                    },
                    "id": 3
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'result' in result:
                    print(f"   ✅ Success: {result['result']}")
                    return result['result']
                elif 'error' in result:
                    print(f"   ❌ Error: {result['error']}")
                    return None
            else:
                print(f"   ❌ HTTP {response.status_code}: {response.text}")
                return None


async def test_with_dynamic_registration():
    """Test flow with dynamic client registration."""
    print("\n" + "="*60)
    print("TEST 1: Dynamic Client Registration Flow")
    print("="*60)
    
    # Create client without credentials
    client = OAuthMCPClient("http://localhost:8000")
    
    # Discover OAuth metadata
    metadata = await client.discover_oauth_metadata()
    
    # Register client dynamically
    if not await client.register_client_dynamically():
        print("❌ Dynamic registration failed!")
        return
    
    # Continue with OAuth flow
    await complete_oauth_flow(client)
    
    # Test MCP functionality
    await test_mcp_functionality(client)


async def test_with_demo_credentials():
    """Test flow with pre-registered demo credentials."""
    print("\n" + "="*60)
    print("TEST 2: Pre-registered Client Flow")
    print("="*60)
    
    # Use demo credentials
    client = OAuthMCPClient(
        server_url="http://localhost:8000",
        client_id="demo_client",
        client_secret="demo_secret",
        redirect_uri="http://localhost:3000/callback"
    )
    
    # Complete OAuth flow
    await complete_oauth_flow(client)
    
    # Test MCP functionality
    await test_mcp_functionality(client)


async def complete_oauth_flow(client: OAuthMCPClient):
    """Complete the OAuth authorization flow."""
    # Generate PKCE
    code_verifier, code_challenge = client.generate_pkce_pair()
    print(f"\n🔐 PKCE generated")
    print(f"   Verifier: {code_verifier[:20]}...")
    print(f"   Challenge: {code_challenge[:20]}...")
    
    # Get authorization URL
    state = secrets.token_urlsafe(16)
    auth_url = client.get_authorization_url(
        code_challenge=code_challenge,
        scope=["read", "write"],
        state=state
    )
    
    # Simulate authorization
    code, returned_state = await client.simulate_authorization(auth_url)
    if not code:
        print("❌ Authorization failed!")
        return
    
    # Verify state
    if returned_state != state:
        print("❌ State mismatch - possible CSRF!")
        return
    
    # Exchange code for token
    token_response = await client.exchange_code_for_token(code, code_verifier)
    if not token_response:
        print("❌ Token exchange failed!")
        return


async def test_mcp_functionality(client: OAuthMCPClient):
    """Test MCP functionality with authenticated client."""
    # Initialize MCP session
    if not await client.initialize_mcp_session():
        print("❌ MCP session initialization failed!")
        return
    
    # List available tools
    tools = await client.list_tools()
    
    # Call tools
    if tools:
        # Test greet tool
        result = await client.call_tool("greet", {"name": "Test User"})
        
        # Test get_secret tool
        result = await client.call_tool("get_secret", {"key": "api_key"})
        
        # Test with invalid key
        result = await client.call_tool("get_secret", {"key": "invalid"})


async def main():
    """Run all tests."""
    print("\n🧪 MCP OAuth Test Client")
    print("="*60)
    print(f"Target server: http://localhost:8000")
    print("="*60)
    
    try:
        # Check if server is running
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get("http://localhost:8000/")
                print("✅ Server is running")
            except:
                print("❌ Server is not running! Please start the MCP server first.")
                return
        
        # Test 1: Dynamic registration
        await test_with_dynamic_registration()
        
        # Test 2: Demo credentials
        await test_with_demo_credentials()
        
        print("\n" + "="*60)
        print("✅ All tests completed!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
