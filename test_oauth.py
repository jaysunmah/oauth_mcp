"""
Simple test script to verify OAuth implementation works correctly.

This performs basic validation of the OAuth provider methods without
running the full server.
"""

import asyncio
from datetime import datetime, timedelta
import pytest
from oauth_provider import InMemoryOAuthProvider
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams


@pytest.mark.asyncio
async def test_oauth_provider():
    """Test the OAuth provider implementation."""
    
    print("="*60)
    print("Testing OAuth Provider Implementation")
    print("="*60)
    
    provider = InMemoryOAuthProvider()
    
    # Test 1: Client Registration
    print("\n✓ Test 1: Client Registration")
    client = OAuthClientInformationFull(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",  # Space-separated string
        token_endpoint_auth_method="client_secret_post",
    )
    await provider.register_client(client)
    print(f"  Registered client: {client.client_id}")
    
    # Test 2: Client Retrieval
    print("\n✓ Test 2: Client Retrieval")
    retrieved_client = await provider.get_client("test_client")
    assert retrieved_client is not None
    assert retrieved_client.client_id == "test_client"
    print(f"  Retrieved client: {retrieved_client.client_id}")
    
    # Test 3: Authorization
    print("\n✓ Test 3: Authorization")
    auth_params = AuthorizationParams(
        scopes=["read", "write"],
        state="random_state_123",
        code_challenge="test_challenge",
        redirect_uri="http://localhost:3000/callback",
        redirect_uri_provided_explicitly=True,
    )
    redirect_url = await provider.authorize(client, auth_params)
    print(f"  Redirect URL: {redirect_url[:80]}...")
    
    # Extract authorization code from redirect
    code = redirect_url.split("code=")[1].split("&")[0]
    print(f"  Authorization code: {code[:20]}...")
    
    # Test 4: Load Authorization Code
    print("\n✓ Test 4: Load Authorization Code")
    auth_code = await provider.load_authorization_code(client, code)
    assert auth_code is not None
    assert auth_code.code == code
    print(f"  Loaded authorization code: {auth_code.code[:20]}...")
    
    # Test 5: Exchange Code for Token
    print("\n✓ Test 5: Exchange Authorization Code for Token")
    token = await provider.exchange_authorization_code(client, auth_code)
    assert token.access_token is not None
    assert token.refresh_token is not None
    print(f"  Access token: {token.access_token[:20]}...")
    print(f"  Refresh token: {token.refresh_token[:20]}...")
    print(f"  Expires in: {token.expires_in} seconds")
    
    # Test 6: Verify Access Token
    print("\n✓ Test 6: Verify Access Token")
    access_token = await provider.verify_token(token.access_token)
    assert access_token is not None
    assert access_token.token == token.access_token
    print(f"  Token verified for client: {access_token.client_id}")
    print(f"  Token scopes: {', '.join(access_token.scopes)}")
    
    # Test 7: Load Refresh Token
    print("\n✓ Test 7: Load Refresh Token")
    refresh_token = await provider.load_refresh_token(client, token.refresh_token)
    assert refresh_token is not None
    print(f"  Loaded refresh token: {refresh_token.token[:20]}...")
    
    # Test 8: Exchange Refresh Token
    print("\n✓ Test 8: Exchange Refresh Token for New Access Token")
    new_token = await provider.exchange_refresh_token(
        client,
        refresh_token,
        ["read"],  # Request fewer scopes
    )
    assert new_token.access_token != token.access_token  # New token
    print(f"  New access token: {new_token.access_token[:20]}...")
    print(f"  New refresh token: {new_token.refresh_token[:20]}...")
    
    # Test 9: Old Refresh Token Should Be Revoked
    print("\n✓ Test 9: Old Refresh Token Revocation")
    old_refresh = await provider.load_refresh_token(client, token.refresh_token)
    assert old_refresh is None  # Should be revoked
    print(f"  Old refresh token successfully revoked")
    
    # Test 10: Token Revocation
    print("\n✓ Test 10: Token Revocation")
    latest_access = await provider.load_access_token(new_token.access_token)
    assert latest_access is not None
    await provider.revoke_token(latest_access)
    
    revoked_access = await provider.verify_token(new_token.access_token)
    assert revoked_access is None  # Should be revoked
    print(f"  Access token successfully revoked")
    
    # Test 11: Invalid Tokens
    print("\n✓ Test 11: Invalid Token Handling")
    invalid = await provider.verify_token("invalid_token_12345")
    assert invalid is None
    print(f"  Invalid token correctly rejected")
    
    # Test 12: Expired Code Handling
    print("\n✓ Test 12: Expired Authorization Code")
    # Create an expired code manually
    from mcp.server.auth.provider import AuthorizationCode
    from pydantic import AnyUrl
    expired_timestamp = (datetime.now() - timedelta(minutes=1)).timestamp()  # Expired
    expired_code = AuthorizationCode(
        code="expired_code_123",
        client_id="test_client",
        redirect_uri=AnyUrl("http://localhost:3000/callback"),
        scopes=["read"],
        code_challenge="challenge",
        expires_at=expired_timestamp,
        redirect_uri_provided_explicitly=True,
    )
    provider.authorization_codes["expired_code_123"] = expired_code
    
    loaded_expired = await provider.load_authorization_code(client, "expired_code_123")
    assert loaded_expired is None  # Should be None due to expiration
    print(f"  Expired authorization code correctly rejected")
    
    print("\n" + "="*60)
    print("✅ All OAuth Provider Tests Passed!")
    print("="*60)
    print("\nYour OAuth implementation is working correctly.")
    print("You can now run the server with: python main.py")
    print("And test the full flow with: python oauth_client_example.py")


if __name__ == "__main__":
    asyncio.run(test_oauth_provider())

