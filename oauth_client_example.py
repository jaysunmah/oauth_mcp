"""
Example OAuth Client Implementation

This demonstrates the OAuth 2.1 flow with PKCE for authenticating
with the FastMCP server.

Flow:
1. Generate PKCE code verifier and challenge
2. Request authorization code
3. Exchange authorization code for access token
4. Use access token to call authenticated tools
5. Refresh token when needed
"""

import asyncio
import hashlib
import base64
import secrets
from urllib.parse import urlencode, parse_qs, urlparse
import httpx


class OAuthClient:
    """Simple OAuth 2.1 client with PKCE support."""
    
    def __init__(
        self,
        server_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        self.server_url = server_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        
        self.access_token: str | None = None
        self.refresh_token: str | None = None
    
    def generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 of verifier)
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(
            challenge_bytes
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(
        self,
        code_challenge: str,
        scope: list[str] | None = None,
        state: str | None = None,
    ) -> str:
        """Build authorization URL for user to visit."""
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
        
        return f"{self.server_url}/oauth/authorize?{urlencode(params)}"
    
    async def exchange_code_for_token(
        self,
        authorization_code: str,
        code_verifier: str,
    ) -> dict:
        """Exchange authorization code for access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.server_url}/oauth/token",
                data={
                    'grant_type': 'authorization_code',
                    'code': authorization_code,
                    'redirect_uri': self.redirect_uri,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'code_verifier': code_verifier,
                },
            )
            response.raise_for_status()
            token_data = response.json()
            
            # Store tokens
            self.access_token = token_data['access_token']
            self.refresh_token = token_data.get('refresh_token')
            
            return token_data
    
    async def refresh_access_token(self) -> dict:
        """Refresh the access token using refresh token."""
        if not self.refresh_token:
            raise ValueError("No refresh token available")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.server_url}/oauth/token",
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': self.refresh_token,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                },
            )
            response.raise_for_status()
            token_data = response.json()
            
            # Update tokens
            self.access_token = token_data['access_token']
            if 'refresh_token' in token_data:
                self.refresh_token = token_data['refresh_token']
            
            return token_data
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call an MCP tool using the access token."""
        if not self.access_token:
            raise ValueError("Not authenticated - no access token")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.server_url}/tools/{tool_name}",
                json=arguments,
                headers={
                    'Authorization': f'Bearer {self.access_token}',
                },
            )
            
            if response.status_code == 401:
                # Try to refresh token and retry
                print("Access token expired, refreshing...")
                await self.refresh_access_token()
                
                # Retry the request
                response = await client.post(
                    f"{self.server_url}/tools/{tool_name}",
                    json=arguments,
                    headers={
                        'Authorization': f'Bearer {self.access_token}',
                    },
                )
            
            response.raise_for_status()
            return response.json()


async def main():
    """Demonstrate OAuth flow."""
    
    # Initialize OAuth client
    oauth_client = OAuthClient(
        server_url="http://localhost:8000",
        client_id="demo_client",
        client_secret="demo_secret",
        redirect_uri="http://localhost:3000/callback",
    )
    
    print("="*60)
    print("OAuth 2.1 Authentication Flow Demo")
    print("="*60)
    
    # Step 1: Generate PKCE pair
    code_verifier, code_challenge = oauth_client.generate_pkce_pair()
    print(f"\n1️⃣  Generated PKCE pair")
    print(f"   Code Verifier: {code_verifier[:20]}...")
    print(f"   Code Challenge: {code_challenge[:20]}...")
    
    # Step 2: Get authorization URL
    state = secrets.token_urlsafe(16)
    auth_url = oauth_client.get_authorization_url(
        code_challenge=code_challenge,
        scope=["read", "write"],
        state=state,
    )
    print(f"\n2️⃣  Authorization URL (in production, user visits this):")
    print(f"   {auth_url}")
    
    # Step 3: Simulate authorization (in production, user approves in browser)
    print(f"\n3️⃣  User authorizes and server redirects back...")
    
    # For this demo, we'll manually extract the code from the simulated redirect
    # In production, this would come from your callback endpoint
    print(f"\n   ⚠️  DEMO MODE: Simulating user authorization...")
    print(f"   In production, the user would:")
    print(f"   - Visit the authorization URL in a browser")
    print(f"   - Log in if not authenticated")
    print(f"   - Approve the requested scopes")
    print(f"   - Get redirected back to {oauth_client.redirect_uri}")
    
    # For demo purposes, we'll make a direct request to the authorize endpoint
    async with httpx.AsyncClient(follow_redirects=False) as client:
        response = await client.get(auth_url)
        
        if response.status_code in (302, 303, 307, 308):
            redirect_location = response.headers['Location']
            parsed = urlparse(redirect_location)
            query_params = parse_qs(parsed.query)
            authorization_code = query_params['code'][0]
            returned_state = query_params.get('state', [None])[0]
            
            print(f"\n4️⃣  Received authorization code:")
            print(f"   Code: {authorization_code[:20]}...")
            print(f"   State: {returned_state}")
            
            # Validate state
            if returned_state != state:
                raise ValueError("State mismatch - possible CSRF attack!")
    
    # Step 4: Exchange code for token
    print(f"\n5️⃣  Exchanging authorization code for access token...")
    token_data = await oauth_client.exchange_code_for_token(
        authorization_code=authorization_code,
        code_verifier=code_verifier,
    )
    
    print(f"   ✅ Access Token: {token_data['access_token'][:20]}...")
    print(f"   ✅ Refresh Token: {token_data['refresh_token'][:20]}...")
    print(f"   ✅ Expires In: {token_data['expires_in']} seconds")
    print(f"   ✅ Scopes: {', '.join(token_data['scope'])}")
    
    # Step 5: Call authenticated tools
    print(f"\n6️⃣  Calling authenticated tools...")
    
    result = await oauth_client.call_tool("greet", {"name": "OAuth User"})
    print(f"   📞 greet('OAuth User') -> {result}")
    
    result = await oauth_client.call_tool("get_secret", {"key": "api_key"})
    print(f"   📞 get_secret('api_key') -> {result}")
    
    # Step 6: Demonstrate token refresh
    print(f"\n7️⃣  Demonstrating token refresh...")
    new_token_data = await oauth_client.refresh_access_token()
    print(f"   ✅ New Access Token: {new_token_data['access_token'][:20]}...")
    print(f"   ✅ New Refresh Token: {new_token_data.get('refresh_token', 'N/A')[:20]}...")
    
    # Test with new token
    result = await oauth_client.call_tool("greet", {"name": "Refreshed Token"})
    print(f"   📞 greet('Refreshed Token') -> {result}")
    
    print("\n" + "="*60)
    print("✅ OAuth Flow Complete!")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())

