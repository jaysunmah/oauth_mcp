#!/usr/bin/env python3
"""
Refactored MCP OAuth Test Suite

This module provides comprehensive testing for the OAuth MCP server implementation.
It consolidates test patterns from multiple test files into a well-structured,
maintainable test suite.

Features:
- OAuth provider functionality tests
- MCP client integration tests
- End-to-end OAuth flow tests
- Error handling and edge case tests
"""

import asyncio
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse

import httpx
from fastmcp import Client

from oauth_provider import InMemoryOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams


# ============================================================================
# Configuration
# ============================================================================

class TestConfig:
    """Test configuration constants."""
    
    SERVER_URL = "http://localhost:8000"
    MCP_ENDPOINT = f"{SERVER_URL}/mcp"
    
    # Demo credentials
    DEMO_CLIENT_ID = "demo_client"
    DEMO_CLIENT_SECRET = "demo_secret"
    DEMO_REDIRECT_URI = "http://localhost:3000/callback"
    
    # Test user
    DEMO_USER_ID = "demo_user"
    DEMO_USER_PASSWORD = "demo_password"
    
    # Test timeouts
    CONNECTION_TIMEOUT = 5.0
    REQUEST_TIMEOUT = 10.0


# ============================================================================
# OAuth Utilities
# ============================================================================

class OAuthTestHelper:
    """Helper class for OAuth test operations."""
    
    @staticmethod
    def generate_pkce_pair() -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(
            challenge_bytes
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    @staticmethod
    def build_authorization_url(
        server_url: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scope: Optional[list[str]] = None,
        state: Optional[str] = None,
    ) -> str:
        """Build OAuth authorization URL."""
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        if scope:
            params['scope'] = ' '.join(scope)
        
        if state:
            params['state'] = state
        
        return f"{server_url}/authorize?{urlencode(params)}"
    
    @staticmethod
    async def simulate_authorization_flow(
        auth_url: str,
        timeout: float = 10.0,
    ) -> tuple[Optional[str], Optional[str]]:
        """Simulate OAuth authorization flow and extract authorization code."""
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
        ) as client:
            response = await client.get(auth_url)
            
            if response.status_code in (302, 303, 307, 308):
                redirect_location = response.headers.get('Location', '')
                parsed = urlparse(redirect_location)
                query_params = parse_qs(parsed.query)
                
                if 'code' in query_params:
                    code = query_params['code'][0]
                    state = query_params.get('state', [None])[0]
                    return code, state
            
            return None, None
    
    @staticmethod
    async def exchange_code_for_token(
        server_url: str,
        authorization_code: str,
        code_verifier: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        timeout: float = 10.0,
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token."""
        async with httpx.AsyncClient(timeout=timeout) as client:
            token_data = {
                'grant_type': 'authorization_code',
                'code': authorization_code,
                'redirect_uri': redirect_uri,
                'client_id': client_id,
                'client_secret': client_secret,
                'code_verifier': code_verifier,
            }
            
            response = await client.post(
                f"{server_url}/token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                return response.json()
            
            return None


# ============================================================================
# OAuth Provider Tests
# ============================================================================

class OAuthProviderTests:
    """Tests for OAuth provider functionality."""
    
    def __init__(self):
        self.provider = InMemoryOAuthProvider()
    
    async def test_client_registration(self) -> bool:
        """Test client registration functionality."""
        print("\n[OAuth Provider] Testing client registration...")
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="read write",
            token_endpoint_auth_method="client_secret_post",
        )
        
        await self.provider.register_client(client)
        retrieved = await self.provider.get_client("test_client")
        
        if retrieved and retrieved.client_id == "test_client":
            print("  ✅ Client registration successful")
            return True
        else:
            print("  ❌ Client registration failed")
            return False
    
    async def test_authorization_flow(self) -> bool:
        """Test OAuth authorization flow."""
        print("\n[OAuth Provider] Testing authorization flow...")
        
        client = await self.provider.get_client("test_client")
        if not client:
            print("  ❌ Test client not found")
            return False
        
        auth_params = AuthorizationParams(
            response_type="code",
            client_id=client.client_id,
            redirect_uri="http://localhost:3000/callback",
            scope=["read", "write"],
            state="test_state_123",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )
        
        try:
            redirect_url = await self.provider.authorize(client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            
            auth_code = await self.provider.load_authorization_code(client, code)
            
            if auth_code and auth_code.code == code:
                print("  ✅ Authorization flow successful")
                return True
            else:
                print("  ❌ Authorization flow failed")
                return False
        except Exception as e:
            print(f"  ❌ Authorization flow error: {e}")
            return False
    
    async def test_token_exchange(self) -> bool:
        """Test token exchange functionality."""
        print("\n[OAuth Provider] Testing token exchange...")
        
        client = await self.provider.get_client("test_client")
        if not client:
            print("  ❌ Test client not found")
            return False
        
        auth_params = AuthorizationParams(
            response_type="code",
            client_id=client.client_id,
            redirect_uri="http://localhost:3000/callback",
            scope=["read", "write"],
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )
        
        redirect_url = await self.provider.authorize(client, auth_params)
        code = redirect_url.split("code=")[1].split("&")[0]
        auth_code = await self.provider.load_authorization_code(client, code)
        
        if not auth_code:
            print("  ❌ Failed to get authorization code")
            return False
        
        token = await self.provider.exchange_authorization_code(client, auth_code)
        
        if token and token.access_token:
            print("  ✅ Token exchange successful")
            return True
        else:
            print("  ❌ Token exchange failed")
            return False
    
    async def run_all_tests(self) -> bool:
        """Run all OAuth provider tests."""
        print("\n" + "="*60)
        print("OAuth Provider Tests")
        print("="*60)
        
        results = []
        results.append(await self.test_client_registration())
        results.append(await self.test_authorization_flow())
        results.append(await self.test_token_exchange())
        
        all_passed = all(results)
        
        print("\n" + "="*60)
        if all_passed:
            print("✅ All OAuth Provider tests passed")
        else:
            print("❌ Some OAuth Provider tests failed")
        print("="*60)
        
        return all_passed


# ============================================================================
# MCP Client Tests
# ============================================================================

class MCPClientTests:
    """Tests for MCP client functionality."""
    
    def __init__(self, config: TestConfig):
        self.config = config
    
    async def check_server_availability(self) -> bool:
        """Check if the MCP server is running."""
        try:
            async with httpx.AsyncClient(timeout=self.config.CONNECTION_TIMEOUT) as client:
                response = await client.get(
                    f"{self.config.SERVER_URL}/.well-known/openid-configuration"
                )
                return response.status_code == 200
        except Exception:
            return False
    
    async def test_mcp_with_oauth(self) -> bool:
        """Test MCP client with OAuth authentication."""
        print("\n[MCP Client] Testing MCP with OAuth...")
        
        if not await self.check_server_availability():
            print("  ⚠️  Server not available, skipping test")
            return False
        
        # Set up OAuth credentials
        import os
        os.environ["OAUTH_CLIENT_ID"] = self.config.DEMO_CLIENT_ID
        os.environ["OAUTH_CLIENT_SECRET"] = self.config.DEMO_CLIENT_SECRET
        
        try:
            client = Client(self.config.MCP_ENDPOINT)
            
            async with client:
                # List available tools
                tools = await client.get_available_tools()
                print(f"  ✅ Connected successfully, found {len(tools)} tools")
                
                # Test greet tool
                result = await client.call_tool("greet", {"name": "Test User"})
                if result and result.content:
                    print(f"  ✅ Greet tool response: {result.content[0].text}")
                    return True
                else:
                    print("  ❌ Greet tool failed")
                    return False
                    
        except Exception as e:
            print(f"  ❌ MCP OAuth test failed: {e}")
            return False
    
    async def test_mcp_without_auth(self) -> bool:
        """Test that MCP requires authentication."""
        print("\n[MCP Client] Testing MCP without auth (should fail)...")
        
        if not await self.check_server_availability():
            print("  ⚠️  Server not available, skipping test")
            return False
        
        import os
        os.environ.pop("OAUTH_CLIENT_ID", None)
        os.environ.pop("OAUTH_CLIENT_SECRET", None)
        
        try:
            client = Client(self.config.MCP_ENDPOINT)
            async with client:
                print("  ❌ Should not have connected without auth")
                return False
        except Exception as e:
            print(f"  ✅ Correctly rejected connection: {str(e)[:100]}...")
            return True
    
    async def run_all_tests(self) -> bool:
        """Run all MCP client tests."""
        print("\n" + "="*60)
        print("MCP Client Tests")
        print("="*60)
        
        if not await self.check_server_availability():
            print("⚠️  Server not available. Please start the server first:")
            print(f"   python main.py")
            return False
        
        results = []
        results.append(await self.test_mcp_with_oauth())
        results.append(await self.test_mcp_without_auth())
        
        all_passed = all(results)
        
        print("\n" + "="*60)
        if all_passed:
            print("✅ All MCP Client tests passed")
        else:
            print("❌ Some MCP Client tests failed")
        print("="*60)
        
        return all_passed


# ============================================================================
# End-to-End OAuth Flow Tests
# ============================================================================

class EndToEndOAuthTests:
    """End-to-end OAuth flow tests."""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.helper = OAuthTestHelper()
    
    async def test_full_oauth_flow(self) -> bool:
        """Test complete OAuth flow from authorization to token usage."""
        print("\n[E2E OAuth] Testing full OAuth flow...")
        
        if not await self.check_server_availability():
            print("  ⚠️  Server not available, skipping test")
            return False
        
        try:
            # Step 1: Generate PKCE
            code_verifier, code_challenge = self.helper.generate_pkce_pair()
            state = secrets.token_urlsafe(16)
            
            # Step 2: Get authorization URL
            auth_url = self.helper.build_authorization_url(
                server_url=self.config.SERVER_URL,
                client_id=self.config.DEMO_CLIENT_ID,
                redirect_uri=self.config.DEMO_REDIRECT_URI,
                code_challenge=code_challenge,
                scope=["read", "write"],
                state=state,
            )
            
            # Step 3: Simulate authorization
            code, returned_state = await self.helper.simulate_authorization_flow(auth_url)
            
            if not code:
                print("  ❌ Failed to get authorization code")
                return False
            
            if returned_state != state:
                print("  ❌ State mismatch - possible CSRF")
                return False
            
            # Step 4: Exchange code for token
            token_response = await self.helper.exchange_code_for_token(
                server_url=self.config.SERVER_URL,
                authorization_code=code,
                code_verifier=code_verifier,
                client_id=self.config.DEMO_CLIENT_ID,
                client_secret=self.config.DEMO_CLIENT_SECRET,
                redirect_uri=self.config.DEMO_REDIRECT_URI,
            )
            
            if not token_response or 'access_token' not in token_response:
                print("  ❌ Failed to exchange code for token")
                return False
            
            print("  ✅ Full OAuth flow completed successfully")
            return True
            
        except Exception as e:
            print(f"  ❌ E2E OAuth flow failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def check_server_availability(self) -> bool:
        """Check if the server is available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.config.SERVER_URL}/.well-known/openid-configuration"
                )
                return response.status_code == 200
        except Exception:
            return False
    
    async def run_all_tests(self) -> bool:
        """Run all end-to-end tests."""
        print("\n" + "="*60)
        print("End-to-End OAuth Tests")
        print("="*60)
        
        if not await self.check_server_availability():
            print("⚠️  Server not available. Please start the server first:")
            print(f"   python main.py")
            return False
        
        results = []
        results.append(await self.test_full_oauth_flow())
        
        all_passed = all(results)
        
        print("\n" + "="*60)
        if all_passed:
            print("✅ All End-to-End tests passed")
        else:
            print("❌ Some End-to-End tests failed")
        print("="*60)
        
        return all_passed


# ============================================================================
# Main Test Runner
# ============================================================================

async def main():
    """Run all test suites."""
    print("\n" + "="*60)
    print("🧪 MCP OAuth Test Suite")
    print("="*60)
    print(f"Server URL: {TestConfig.SERVER_URL}")
    print("="*60)
    
    config = TestConfig()
    results = {}
    
    # Run OAuth Provider tests (doesn't require server)
    provider_tests = OAuthProviderTests()
    results['provider'] = await provider_tests.run_all_tests()
    
    # Run MCP Client tests (requires server)
    client_tests = MCPClientTests(config)
    results['client'] = await client_tests.run_all_tests()
    
    # Run End-to-End tests (requires server)
    e2e_tests = EndToEndOAuthTests(config)
    results['e2e'] = await e2e_tests.run_all_tests()
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Summary")
    print("="*60)
    print(f"OAuth Provider Tests: {'✅ PASSED' if results['provider'] else '❌ FAILED'}")
    print(f"MCP Client Tests:     {'✅ PASSED' if results['client'] else '❌ FAILED'}")
    print(f"End-to-End Tests:     {'✅ PASSED' if results['e2e'] else '❌ FAILED'}")
    print("="*60)
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
    
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
