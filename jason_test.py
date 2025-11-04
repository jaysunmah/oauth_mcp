"""
Comprehensive test suite for OAuth Provider metadata and dynamic client registration.

This test file focuses on testing the OAuth metadata endpoint and DCR functionality.
"""

import asyncio
from oauth_provider import InMemoryOAuthProvider, ClientRegistrationRequest


async def test_oauth_metadata():
    """Test OAuth metadata generation and structure."""
    
    print("="*60)
    print("Testing OAuth Metadata Implementation")
    print("="*60)
    
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    
    # Test 1: Metadata Structure
    print("\n✓ Test 1: Metadata Structure")
    metadata = provider.metadata
    assert isinstance(metadata, dict)
    assert "registration_endpoint" in metadata
    assert "registration_endpoint_auth_methods_supported" in metadata
    assert "client_registration_types_supported" in metadata
    assert "require_client_authentication" in metadata
    print(f"  Metadata contains all required fields")
    
    # Test 2: Registration Endpoint Format
    print("\n✓ Test 2: Registration Endpoint Format")
    assert metadata["registration_endpoint"] == "http://localhost:8000/register"
    print(f"  Registration endpoint: {metadata['registration_endpoint']}")
    
    # Test 3: Custom Base URL
    print("\n✓ Test 3: Custom Base URL")
    custom_provider = InMemoryOAuthProvider(base_url="https://oauth.example.com:9000")
    custom_metadata = custom_provider.metadata
    assert custom_metadata["registration_endpoint"] == "https://oauth.example.com:9000/register"
    print(f"  Custom base URL works correctly: {custom_metadata['registration_endpoint']}")
    
    # Test 4: Auth Methods Supported
    print("\n✓ Test 4: Registration Endpoint Auth Methods")
    assert isinstance(metadata["registration_endpoint_auth_methods_supported"], list)
    assert "none" in metadata["registration_endpoint_auth_methods_supported"]
    print(f"  Auth methods: {metadata['registration_endpoint_auth_methods_supported']}")
    
    # Test 5: Registration Types Supported
    print("\n✓ Test 5: Client Registration Types")
    assert isinstance(metadata["client_registration_types_supported"], list)
    assert "automatic" in metadata["client_registration_types_supported"]
    print(f"  Registration types: {metadata['client_registration_types_supported']}")
    
    # Test 6: Client Authentication Requirement
    print("\n✓ Test 6: Client Authentication Requirement")
    assert metadata["require_client_authentication"] is False
    print(f"  Client authentication required: {metadata['require_client_authentication']}")


async def test_dynamic_client_registration():
    """Test dynamic client registration functionality."""
    
    print("\n" + "="*60)
    print("Testing Dynamic Client Registration (DCR)")
    print("="*60)
    
    provider = InMemoryOAuthProvider()
    
    # Test 1: Basic Registration
    print("\n✓ Test 1: Basic Dynamic Client Registration")
    registration_request = ClientRegistrationRequest(
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="Test Client",
    )
    
    response = await provider.dynamic_register_client(registration_request)
    assert response.client_id is not None
    assert response.client_secret is not None
    assert response.client_id_issued_at > 0
    assert response.redirect_uris == registration_request.redirect_uris
    assert response.grant_types == registration_request.grant_types
    assert response.response_types == registration_request.response_types
    print(f"  Registered client: {response.client_id}")
    print(f"  Client secret: {response.client_secret[:20]}...")
    print(f"  Issued at: {response.client_id_issued_at}")
    
    # Test 2: Minimal Fields Registration
    print("\n✓ Test 2: Registration with Minimal Fields")
    minimal_request = ClientRegistrationRequest(
        redirect_uris=["http://localhost:3000/callback"]
    )
    
    minimal_response = await provider.dynamic_register_client(minimal_request)
    assert minimal_response.client_id is not None
    assert minimal_response.client_secret is not None
    print(f"  Minimal registration successful: {minimal_response.client_id}")
    
    # Test 3: Client Storage Verification
    print("\n✓ Test 3: Client Storage Verification")
    stored_client = await provider.get_client(response.client_id)
    assert stored_client is not None
    assert stored_client.client_id == response.client_id
    assert stored_client.client_secret == response.client_secret
    assert stored_client.redirect_uris == response.redirect_uris
    print(f"  Client correctly stored and retrievable")
    
    # Test 4: Empty Redirect URIs Validation
    print("\n✓ Test 4: Empty Redirect URIs Validation")
    invalid_request = ClientRegistrationRequest(
        redirect_uris=[]
    )
    
    try:
        await provider.dynamic_register_client(invalid_request)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "redirect_uris" in str(e)
        print(f"  Empty redirect_uris correctly rejected: {str(e)}")
    
    # Test 5: Automatic Refresh Token Grant Addition
    print("\n✓ Test 5: Automatic Refresh Token Grant Addition")
    auth_code_only_request = ClientRegistrationRequest(
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code"],  # Missing refresh_token
    )
    
    auth_code_response = await provider.dynamic_register_client(auth_code_only_request)
    assert "authorization_code" in auth_code_response.grant_types
    assert "refresh_token" in auth_code_response.grant_types
    print(f"  Refresh token grant automatically added")
    print(f"  Final grant types: {auth_code_response.grant_types}")
    
    # Test 6: Full Registration with All Fields
    print("\n✓ Test 6: Registration with All Optional Fields")
    full_request = ClientRegistrationRequest(
        redirect_uris=[
            "http://localhost:3000/callback",
            "http://localhost:3001/callback"
        ],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="Full Client",
        client_uri="http://example.com",
        logo_uri="http://example.com/logo.png",
        scope="read write admin",
        contacts=["admin@example.com"],
        tos_uri="http://example.com/tos",
        policy_uri="http://example.com/policy",
        token_endpoint_auth_method="client_secret_post",
    )
    
    full_response = await provider.dynamic_register_client(full_request)
    assert full_response.client_name == "Full Client"
    assert full_response.client_uri == "http://example.com"
    assert full_response.logo_uri == "http://example.com/logo.png"
    assert full_response.scope == "read write admin"
    assert full_response.contacts == ["admin@example.com"]
    assert full_response.tos_uri == "http://example.com/tos"
    assert full_response.policy_uri == "http://example.com/policy"
    assert full_response.token_endpoint_auth_method == "client_secret_post"
    print(f"  All fields correctly stored:")
    print(f"    Name: {full_response.client_name}")
    print(f"    URI: {full_response.client_uri}")
    print(f"    Scope: {full_response.scope}")
    print(f"    Contacts: {full_response.contacts}")


async def test_metadata_integration():
    """Test metadata integration with client registration."""
    
    print("\n" + "="*60)
    print("Testing Metadata Integration")
    print("="*60)
    
    # Test 1: Metadata Endpoints Match Registration
    print("\n✓ Test 1: Metadata Endpoints Match Registration")
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    metadata = provider.metadata
    
    registration_request = ClientRegistrationRequest(
        redirect_uris=["http://localhost:3000/callback"]
    )
    
    response = await provider.dynamic_register_client(registration_request)
    assert response.client_id is not None
    assert metadata["registration_endpoint"] == "http://localhost:8000/register"
    print(f"  Metadata registration endpoint matches: {metadata['registration_endpoint']}")
    
    # Test 2: Base URL Consistency
    print("\n✓ Test 2: Base URL Consistency")
    base_url = "https://oauth.example.com"
    custom_provider = InMemoryOAuthProvider(base_url=base_url)
    custom_metadata = custom_provider.metadata
    
    assert custom_metadata["registration_endpoint"].startswith(base_url)
    print(f"  Base URL consistent across metadata: {custom_metadata['registration_endpoint']}")


async def main():
    """Run all metadata and DCR tests."""
    try:
        await test_oauth_metadata()
        await test_dynamic_client_registration()
        await test_metadata_integration()
        
        print("\n" + "="*60)
        print("✅ All OAuth Metadata and DCR Tests Passed!")
        print("="*60)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {str(e)}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(main())
