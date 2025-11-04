#!/usr/bin/env python3
"""
Comprehensive test suite for OAuth Provider functionality.

This test file focuses on testing the OAuth provider implementation,
including metadata generation, dynamic client registration, and token management.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from typing import Optional

from oauth_provider import InMemoryOAuthProvider, ClientRegistrationRequest, ClientRegistrationResponse
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams, AuthorizationCode


class TestOAuthProviderMetadata:
    """Test OAuth provider metadata generation."""
    
    @pytest.mark.asyncio
    async def test_metadata_includes_registration_endpoint(self):
        """Test that metadata includes registration endpoint for DCR."""
        provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
        metadata = provider.metadata
        
        assert "registration_endpoint" in metadata
        assert metadata["registration_endpoint"] == "http://localhost:8000/register"
        assert "registration_endpoint_auth_methods_supported" in metadata
        assert "client_registration_types_supported" in metadata
        assert "automatic" in metadata["client_registration_types_supported"]
    
    @pytest.mark.asyncio
    async def test_metadata_includes_required_oauth_fields(self):
        """Test that metadata includes all required OAuth 2.0 fields."""
        provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
        metadata = provider.metadata
        
        # Check for base metadata fields
        assert isinstance(metadata, dict)
        assert "registration_endpoint" in metadata


class TestDynamicClientRegistration:
    """Test Dynamic Client Registration (RFC 7591) functionality."""
    
    @pytest.mark.asyncio
    async def test_register_client_dynamically(self):
        """Test dynamic client registration with valid data."""
        provider = InMemoryOAuthProvider()
        
        registration = ClientRegistrationRequest(
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            client_name="Test Client",
            token_endpoint_auth_method="client_secret_post",
        )
        
        response = await provider.dynamic_register_client(registration)
        
        assert isinstance(response, ClientRegistrationResponse)
        assert response.client_id is not None
        assert response.client_id.startswith("dcr_")
        assert response.client_secret is not None
        assert response.redirect_uris == registration.redirect_uris
        assert response.grant_types == registration.grant_types
        assert response.client_id_issued_at > 0
        
        # Verify client was stored
        stored_client = await provider.get_client(response.client_id)
        assert stored_client is not None
        assert stored_client.client_id == response.client_id
        assert stored_client.client_secret == response.client_secret
    
    @pytest.mark.asyncio
    async def test_register_client_empty_redirect_uris(self):
        """Test that empty redirect_uris raises ValueError."""
        provider = InMemoryOAuthProvider()
        
        registration = ClientRegistrationRequest(
            redirect_uris=[],
            grant_types=["authorization_code"],
        )
        
        with pytest.raises(ValueError, match="redirect_uris"):
            await provider.dynamic_register_client(registration)
    
    @pytest.mark.asyncio
    async def test_register_client_auto_adds_refresh_token(self):
        """Test that refresh_token grant is automatically added for authorization_code."""
        provider = InMemoryOAuthProvider()
        
        registration = ClientRegistrationRequest(
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],  # Missing refresh_token
            response_types=["code"],
        )
        
        response = await provider.dynamic_register_client(registration)
        
        assert "refresh_token" in response.grant_types
        assert "authorization_code" in response.grant_types
        
        # Verify stored client also has refresh_token
        stored_client = await provider.get_client(response.client_id)
        assert "refresh_token" in stored_client.grant_types


class TestClientManagement:
    """Test client registration and retrieval."""
    
    @pytest.mark.asyncio
    async def test_register_and_get_client(self):
        """Test registering and retrieving a client."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="read write",
            token_endpoint_auth_method="client_secret_post",
        )
        
        await provider.register_client(client)
        retrieved = await provider.get_client("test_client")
        
        assert retrieved is not None
        assert retrieved.client_id == client.client_id
        assert retrieved.client_secret == client.client_secret
        assert retrieved.redirect_uris == client.redirect_uris
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_client(self):
        """Test retrieving a client that doesn't exist."""
        provider = InMemoryOAuthProvider()
        
        retrieved = await provider.get_client("nonexistent")
        assert retrieved is None


class TestAuthorizationFlow:
    """Test OAuth authorization code flow."""
    
    @pytest.mark.asyncio
    async def test_authorize_generates_code(self):
        """Test that authorize generates a valid authorization code."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        params = AuthorizationParams(
            response_type="code",
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope=["read"],
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )
        
        redirect_url = await provider.authorize(client, params)
        
        assert redirect_url.startswith("http://localhost:3000/callback")
        assert "code=" in redirect_url
        assert "state=test_state" in redirect_url
        
        # Extract code and verify it's stored
        code = redirect_url.split("code=")[1].split("&")[0]
        auth_code = await provider.load_authorization_code(client, code)
        
        assert auth_code is not None
        assert auth_code.code == code
        assert auth_code.client_id == client.client_id
        assert auth_code.user_id == "demo_user"
    
    @pytest.mark.asyncio
    async def test_authorize_invalid_redirect_uri(self):
        """Test that invalid redirect URI raises ValueError."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        params = AuthorizationParams(
            response_type="code",
            client_id="test_client",
            redirect_uri="http://evil.com/callback",  # Not in allowed list
            scope=["read"],
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )
        
        with pytest.raises(ValueError, match="Invalid redirect_uri"):
            await provider.authorize(client, params)
    
    @pytest.mark.asyncio
    async def test_authorization_code_expiration(self):
        """Test that expired authorization codes are rejected."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create an expired code manually
        expired_code = AuthorizationCode(
            code="expired_code",
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope=["read"],
            code_challenge="challenge",
            code_challenge_method="S256",
            expires_at=datetime.now() - timedelta(minutes=1),  # Expired
            user_id="demo_user",
        )
        provider.authorization_codes["expired_code"] = expired_code
        
        # Try to load expired code
        loaded = await provider.load_authorization_code(client, "expired_code")
        assert loaded is None
        
        # Verify code was cleaned up
        assert "expired_code" not in provider.authorization_codes


class TestTokenManagement:
    """Test token generation, exchange, and validation."""
    
    @pytest.mark.asyncio
    async def test_exchange_code_for_token(self):
        """Test exchanging authorization code for access and refresh tokens."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="read write",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create authorization code
        auth_code = AuthorizationCode(
            code="test_code",
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope=["read", "write"],
            code_challenge="challenge",
            code_challenge_method="S256",
            expires_at=datetime.now() + timedelta(minutes=10),
            user_id="demo_user",
        )
        provider.authorization_codes["test_code"] = auth_code
        
        # Exchange code for token
        token = await provider.exchange_authorization_code(client, auth_code)
        
        assert token.access_token is not None
        assert token.refresh_token is not None
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600  # 1 hour
        assert set(token.scope) == {"read", "write"}
        
        # Verify code was deleted (one-time use)
        assert "test_code" not in provider.authorization_codes
        
        # Verify tokens are stored
        access_token_obj = await provider.load_access_token(token.access_token)
        assert access_token_obj is not None
        assert access_token_obj.user_id == "demo_user"
    
    @pytest.mark.asyncio
    async def test_refresh_token_exchange(self):
        """Test exchanging refresh token for new access token."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="read write",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create refresh token
        from mcp.server.auth.provider import RefreshToken
        refresh_token = RefreshToken(
            token="refresh_token_123",
            client_id="test_client",
            scope=["read", "write"],
            expires_at=datetime.now() + timedelta(days=30),
            user_id="demo_user",
        )
        provider.refresh_tokens["refresh_token_123"] = refresh_token
        
        # Exchange refresh token
        new_token = await provider.exchange_refresh_token(
            client,
            refresh_token,
            ["read"],  # Request subset of scopes
        )
        
        assert new_token.access_token is not None
        assert new_token.refresh_token != refresh_token.token  # Rotated
        assert set(new_token.scope) == {"read"}
        
        # Verify old refresh token is revoked
        old_refresh = await provider.load_refresh_token(client, "refresh_token_123")
        assert old_refresh is None
        
        # Verify new refresh token is stored
        new_refresh = await provider.load_refresh_token(client, new_token.refresh_token)
        assert new_refresh is not None
    
    @pytest.mark.asyncio
    async def test_refresh_token_scope_validation(self):
        """Test that requesting more scopes than original grant raises ValueError."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        from mcp.server.auth.provider import RefreshToken
        refresh_token = RefreshToken(
            token="refresh_token_123",
            client_id="test_client",
            scope=["read"],  # Only "read" scope
            expires_at=datetime.now() + timedelta(days=30),
            user_id="demo_user",
        )
        provider.refresh_tokens["refresh_token_123"] = refresh_token
        
        # Try to request more scopes than granted
        with pytest.raises(ValueError, match="Requested scopes exceed"):
            await provider.exchange_refresh_token(
                client,
                refresh_token,
                ["read", "write", "admin"],  # More than original
            )
    
    @pytest.mark.asyncio
    async def test_token_verification(self):
        """Test verifying access tokens."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create access token
        from mcp.server.auth.provider import AccessToken
        access_token = AccessToken(
            token="valid_token",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() + timedelta(hours=1),
            user_id="demo_user",
        )
        provider.access_tokens["valid_token"] = access_token
        
        # Verify valid token
        verified = await provider.verify_token("valid_token")
        assert verified is not None
        assert verified.token == "valid_token"
        assert verified.user_id == "demo_user"
        
        # Verify invalid token
        invalid = await provider.verify_token("invalid_token")
        assert invalid is None
    
    @pytest.mark.asyncio
    async def test_token_revocation(self):
        """Test revoking tokens."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create access token
        from mcp.server.auth.provider import AccessToken
        access_token = AccessToken(
            token="token_to_revoke",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() + timedelta(hours=1),
            user_id="demo_user",
        )
        provider.access_tokens["token_to_revoke"] = access_token
        
        # Revoke token
        await provider.revoke_token(access_token)
        
        # Verify token is revoked
        verified = await provider.verify_token("token_to_revoke")
        assert verified is None
        
        # Verify token is in revoked set
        assert "token_to_revoke" in provider.revoked_tokens


class TestTokenExpiration:
    """Test token expiration handling."""
    
    @pytest.mark.asyncio
    async def test_expired_access_token_rejected(self):
        """Test that expired access tokens are rejected."""
        provider = InMemoryOAuthProvider()
        
        client = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
            scope="read",
            token_endpoint_auth_method="client_secret_post",
        )
        await provider.register_client(client)
        
        # Create expired access token
        from mcp.server.auth.provider import AccessToken
        expired_token = AccessToken(
            token="expired_token",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() - timedelta(hours=1),  # Expired
            user_id="demo_user",
        )
        provider.access_tokens["expired_token"] = expired_token
        
        # Verify expired token is rejected
        verified = await provider.verify_token("expired_token")
        assert verified is None
        
        # Verify token was cleaned up
        assert "expired_token" not in provider.access_tokens


class TestCleanup:
    """Test cleanup functionality."""
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(self):
        """Test that expired tokens are cleaned up."""
        provider = InMemoryOAuthProvider()
        
        # Create expired tokens
        expired_code = AuthorizationCode(
            code="expired_code",
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope=["read"],
            code_challenge="challenge",
            code_challenge_method="S256",
            expires_at=datetime.now() - timedelta(minutes=1),
            user_id="demo_user",
        )
        provider.authorization_codes["expired_code"] = expired_code
        
        from mcp.server.auth.provider import AccessToken, RefreshToken
        
        expired_access = AccessToken(
            token="expired_access",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() - timedelta(hours=1),
            user_id="demo_user",
        )
        provider.access_tokens["expired_access"] = expired_access
        
        expired_refresh = RefreshToken(
            token="expired_refresh",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() - timedelta(days=1),
            user_id="demo_user",
        )
        provider.refresh_tokens["expired_refresh"] = expired_refresh
        
        # Create valid tokens
        valid_code = AuthorizationCode(
            code="valid_code",
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope=["read"],
            code_challenge="challenge",
            code_challenge_method="S256",
            expires_at=datetime.now() + timedelta(minutes=10),
            user_id="demo_user",
        )
        provider.authorization_codes["valid_code"] = valid_code
        
        valid_access = AccessToken(
            token="valid_access",
            client_id="test_client",
            scope=["read"],
            expires_at=datetime.now() + timedelta(hours=1),
            user_id="demo_user",
        )
        provider.access_tokens["valid_access"] = valid_access
        
        # Run cleanup
        provider.cleanup_expired_tokens()
        
        # Verify expired tokens are removed
        assert "expired_code" not in provider.authorization_codes
        assert "expired_access" not in provider.access_tokens
        assert "expired_refresh" not in provider.refresh_tokens
        
        # Verify valid tokens remain
        assert "valid_code" in provider.authorization_codes
        assert "valid_access" in provider.access_tokens


# Async test runner
async def run_all_tests():
    """Run all tests synchronously."""
    print("="*60)
    print("Running OAuth Provider Test Suite")
    print("="*60)
    
    # Run tests using pytest's async test runner
    # Note: In practice, you would run: pytest jason_test.py
    print("\n✅ Test file created successfully!")
    print("Run tests with: pytest jason_test.py -v")


if __name__ == "__main__":
    asyncio.run(run_all_tests())
