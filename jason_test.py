#!/usr/bin/env python3
"""
Comprehensive OAuth Provider Test Suite

This test suite validates the OAuth provider implementation with comprehensive
coverage of all OAuth 2.1 flows including:
- Client registration and retrieval
- Authorization code flow
- Token exchange and refresh
- Token verification and revocation
- Error handling and edge cases

Copyright Anysphere Inc.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional

from oauth_provider import InMemoryOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams, AuthorizationCode


class OAuthTestSuite:
    """Test suite for OAuth provider implementation."""
    
    def __init__(self):
        """Initialize test suite with provider instance."""
        self.provider = InMemoryOAuthProvider()
        self.test_client: Optional[OAuthClientInformationFull] = None
        self.passed_tests = 0
        self.failed_tests = 0
    
    def print_header(self, title: str) -> None:
        """Print formatted test section header."""
        print("\n" + "=" * 60)
        print(f"  {title}")
        print("=" * 60)
    
    def print_test(self, test_name: str, passed: bool = True) -> None:
        """Print test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"\n{status}: {test_name}")
        if passed:
            self.passed_tests += 1
        else:
            self.failed_tests += 1
    
    async def test_client_registration(self) -> bool:
        """Test client registration functionality."""
        self.print_header("Test 1: Client Registration")
        
        try:
            self.test_client = OAuthClientInformationFull(
                client_id="test_client",
                client_secret="test_secret",
                redirect_uris=["http://localhost:3000/callback"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope="read write",
                token_endpoint_auth_method="client_secret_post",
            )
            await self.provider.register_client(self.test_client)
            self.print_test("Client registration")
            return True
        except Exception as e:
            self.print_test(f"Client registration failed: {e}", False)
            return False
    
    async def test_client_retrieval(self) -> bool:
        """Test client retrieval functionality."""
        self.print_header("Test 2: Client Retrieval")
        
        try:
            retrieved_client = await self.provider.get_client("test_client")
            assert retrieved_client is not None, "Client not found"
            assert retrieved_client.client_id == "test_client", "Client ID mismatch"
            assert retrieved_client.client_secret == "test_secret", "Client secret mismatch"
            self.print_test("Client retrieval")
            return True
        except AssertionError as e:
            self.print_test(f"Client retrieval failed: {e}", False)
            return False
        except Exception as e:
            self.print_test(f"Client retrieval error: {e}", False)
            return False
    
    async def test_authorization_flow(self) -> bool:
        """Test OAuth authorization flow."""
        self.print_header("Test 3: Authorization Flow")
        
        try:
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="random_state_123",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            
            assert redirect_url.startswith("http://localhost:3000/callback"), "Invalid redirect URL"
            assert "code=" in redirect_url, "Authorization code missing"
            assert "state=random_state_123" in redirect_url, "State parameter missing"
            
            self.print_test("Authorization flow")
            return True
        except Exception as e:
            self.print_test(f"Authorization flow failed: {e}", False)
            return False
    
    async def test_authorization_code_loading(self) -> bool:
        """Test loading authorization code."""
        self.print_header("Test 4: Authorization Code Loading")
        
        try:
            # Create a new authorization code
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            
            # Load the authorization code
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            assert auth_code is not None, "Failed to load authorization code"
            assert auth_code.code == code, "Code mismatch"
            assert auth_code.client_id == "test_client", "Client ID mismatch"
            
            self.print_test("Authorization code loading")
            return True
        except Exception as e:
            self.print_test(f"Authorization code loading failed: {e}", False)
            return False
    
    async def test_token_exchange(self) -> bool:
        """Test exchanging authorization code for token."""
        self.print_header("Test 5: Token Exchange")
        
        try:
            # Create authorization code
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            
            # Exchange code for token
            token = await self.provider.exchange_authorization_code(self.test_client, auth_code)
            assert token.access_token is not None, "Access token missing"
            assert token.refresh_token is not None, "Refresh token missing"
            assert token.expires_in > 0, "Invalid expiration time"
            assert token.token_type == "Bearer", "Invalid token type"
            
            self.print_test("Token exchange")
            return True
        except Exception as e:
            self.print_test(f"Token exchange failed: {e}", False)
            return False
    
    async def test_token_verification(self) -> bool:
        """Test access token verification."""
        self.print_header("Test 6: Token Verification")
        
        try:
            # Create and exchange authorization code
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            token = await self.provider.exchange_authorization_code(self.test_client, auth_code)
            
            # Verify token
            access_token = await self.provider.verify_token(token.access_token)
            assert access_token is not None, "Token verification failed"
            assert access_token.token == token.access_token, "Token mismatch"
            assert access_token.user_id == "demo_user", "User ID mismatch"
            assert len(access_token.scope) > 0, "Scope missing"
            
            self.print_test("Token verification")
            return True
        except Exception as e:
            self.print_test(f"Token verification failed: {e}", False)
            return False
    
    async def test_refresh_token_loading(self) -> bool:
        """Test loading refresh token."""
        self.print_header("Test 7: Refresh Token Loading")
        
        try:
            # Get refresh token from previous exchange
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            token = await self.provider.exchange_authorization_code(self.test_client, auth_code)
            
            # Load refresh token
            refresh_token = await self.provider.load_refresh_token(
                self.test_client, token.refresh_token
            )
            assert refresh_token is not None, "Failed to load refresh token"
            assert refresh_token.token == token.refresh_token, "Refresh token mismatch"
            
            self.print_test("Refresh token loading")
            return True
        except Exception as e:
            self.print_test(f"Refresh token loading failed: {e}", False)
            return False
    
    async def test_refresh_token_exchange(self) -> bool:
        """Test exchanging refresh token for new access token."""
        self.print_header("Test 8: Refresh Token Exchange")
        
        try:
            # Get initial token
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            original_token = await self.provider.exchange_authorization_code(
                self.test_client, auth_code
            )
            
            # Load refresh token
            refresh_token = await self.provider.load_refresh_token(
                self.test_client, original_token.refresh_token
            )
            
            # Exchange refresh token
            new_token = await self.provider.exchange_refresh_token(
                self.test_client, refresh_token, ["read"]
            )
            assert new_token.access_token != original_token.access_token, "Token not rotated"
            assert new_token.refresh_token != original_token.refresh_token, "Refresh token not rotated"
            
            self.print_test("Refresh token exchange")
            return True
        except Exception as e:
            self.print_test(f"Refresh token exchange failed: {e}", False)
            return False
    
    async def test_refresh_token_revocation(self) -> bool:
        """Test that old refresh token is revoked after exchange."""
        self.print_header("Test 9: Refresh Token Revocation")
        
        try:
            # Get initial token
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            original_token = await self.provider.exchange_authorization_code(
                self.test_client, auth_code
            )
            
            # Exchange refresh token (this should revoke the old one)
            refresh_token = await self.provider.load_refresh_token(
                self.test_client, original_token.refresh_token
            )
            await self.provider.exchange_refresh_token(
                self.test_client, refresh_token, ["read"]
            )
            
            # Verify old refresh token is revoked
            old_refresh = await self.provider.load_refresh_token(
                self.test_client, original_token.refresh_token
            )
            assert old_refresh is None, "Old refresh token should be revoked"
            
            self.print_test("Refresh token revocation")
            return True
        except Exception as e:
            self.print_test(f"Refresh token revocation test failed: {e}", False)
            return False
    
    async def test_token_revocation(self) -> bool:
        """Test token revocation functionality."""
        self.print_header("Test 10: Token Revocation")
        
        try:
            # Get token
            auth_params = AuthorizationParams(
                response_type="code",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read", "write"],
                state="test_state",
                code_challenge="test_challenge",
                code_challenge_method="S256",
            )
            redirect_url = await self.provider.authorize(self.test_client, auth_params)
            code = redirect_url.split("code=")[1].split("&")[0]
            auth_code = await self.provider.load_authorization_code(self.test_client, code)
            token = await self.provider.exchange_authorization_code(self.test_client, auth_code)
            
            # Revoke token
            access_token = await self.provider.load_access_token(token.access_token)
            assert access_token is not None, "Failed to load access token"
            await self.provider.revoke_token(access_token)
            
            # Verify token is revoked
            revoked_token = await self.provider.verify_token(token.access_token)
            assert revoked_token is None, "Token should be revoked"
            
            self.print_test("Token revocation")
            return True
        except Exception as e:
            self.print_test(f"Token revocation failed: {e}", False)
            return False
    
    async def test_invalid_token_handling(self) -> bool:
        """Test handling of invalid tokens."""
        self.print_header("Test 11: Invalid Token Handling")
        
        try:
            invalid_token = await self.provider.verify_token("invalid_token_12345")
            assert invalid_token is None, "Invalid token should be rejected"
            
            self.print_test("Invalid token handling")
            return True
        except Exception as e:
            self.print_test(f"Invalid token handling test failed: {e}", False)
            return False
    
    async def test_expired_code_handling(self) -> bool:
        """Test handling of expired authorization codes."""
        self.print_header("Test 12: Expired Authorization Code Handling")
        
        try:
            # Create an expired code manually
            expired_code = AuthorizationCode(
                code="expired_code_123",
                client_id="test_client",
                redirect_uri="http://localhost:3000/callback",
                scope=["read"],
                code_challenge="challenge",
                code_challenge_method="S256",
                expires_at=datetime.now() - timedelta(minutes=1),  # Expired
                user_id="demo_user",
            )
            self.provider.authorization_codes["expired_code_123"] = expired_code
            
            # Try to load expired code
            loaded_expired = await self.provider.load_authorization_code(
                self.test_client, "expired_code_123"
            )
            assert loaded_expired is None, "Expired code should be rejected"
            
            self.print_test("Expired code handling")
            return True
        except Exception as e:
            self.print_test(f"Expired code handling test failed: {e}", False)
            return False
    
    async def run_all_tests(self) -> None:
        """Run all tests in the suite."""
        print("\n" + "=" * 60)
        print("  OAuth Provider Test Suite")
        print("=" * 60)
        
        tests = [
            self.test_client_registration,
            self.test_client_retrieval,
            self.test_authorization_flow,
            self.test_authorization_code_loading,
            self.test_token_exchange,
            self.test_token_verification,
            self.test_refresh_token_loading,
            self.test_refresh_token_exchange,
            self.test_refresh_token_revocation,
            self.test_token_revocation,
            self.test_invalid_token_handling,
            self.test_expired_code_handling,
        ]
        
        for test in tests:
            try:
                await test()
            except Exception as e:
                print(f"\n❌ Unexpected error in {test.__name__}: {e}")
                import traceback
                traceback.print_exc()
                self.failed_tests += 1
        
        # Print summary
        self.print_summary()
    
    def print_summary(self) -> None:
        """Print test execution summary."""
        print("\n" + "=" * 60)
        print("  Test Summary")
        print("=" * 60)
        print(f"  ✅ Passed: {self.passed_tests}")
        print(f"  ❌ Failed: {self.failed_tests}")
        print(f"  📊 Total:  {self.passed_tests + self.failed_tests}")
        
        if self.failed_tests == 0:
            print("\n" + "=" * 60)
            print("  ✅ All OAuth Provider Tests Passed!")
            print("=" * 60)
            print("\nYour OAuth implementation is working correctly.")
            print("You can now run the server with: python main.py")
            print("And test the full flow with: python oauth_client_example.py")
        else:
            print("\n" + "=" * 60)
            print("  ⚠️  Some tests failed. Please review the errors above.")
            print("=" * 60)


async def main():
    """Main entry point for test suite."""
    suite = OAuthTestSuite()
    await suite.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
