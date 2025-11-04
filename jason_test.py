"""
Comprehensive test suite for OAuth Provider metadata and dynamic client registration.

This test file focuses on testing the OAuth metadata endpoint and DCR functionality.
"""

import asyncio
from typing import Dict, Any
from oauth_provider import InMemoryOAuthProvider, ClientRegistrationRequest


# Test constants
DEFAULT_BASE_URL = "http://localhost:8000"
CUSTOM_BASE_URL = "https://oauth.example.com:9000"
TEST_REDIRECT_URI = "http://localhost:3000/callback"
SECOND_REDIRECT_URI = "http://localhost:3001/callback"
TEST_CLIENT_NAME = "Test Client"
FULL_CLIENT_NAME = "Full Client"
EXAMPLE_BASE_URL = "https://oauth.example.com"

# Expected metadata fields
REQUIRED_METADATA_FIELDS = [
    "registration_endpoint",
    "registration_endpoint_auth_methods_supported",
    "client_registration_types_supported",
    "require_client_authentication",
]


def print_section_header(title: str) -> None:
    """Print a formatted section header."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def print_test_header(test_number: int, test_name: str) -> None:
    """Print a formatted test header."""
    print(f"\n✓ Test {test_number}: {test_name}")


def assert_metadata_structure(metadata: Dict[str, Any], expected_fields: list[str]) -> None:
    """Assert that metadata contains all required fields."""
    assert isinstance(metadata, dict), "Metadata must be a dictionary"
    for field in expected_fields:
        assert field in metadata, f"Metadata missing required field: {field}"


async def test_oauth_metadata():
    """Test OAuth metadata generation and structure."""
    print_section_header("Testing OAuth Metadata Implementation")
    
    provider = InMemoryOAuthProvider(base_url=DEFAULT_BASE_URL)
    metadata = provider.metadata
    
    # Test 1: Metadata Structure
    print_test_header(1, "Metadata Structure")
    assert_metadata_structure(metadata, REQUIRED_METADATA_FIELDS)
    print("  Metadata contains all required fields")
    
    # Test 2: Registration Endpoint Format
    print_test_header(2, "Registration Endpoint Format")
    expected_endpoint = f"{DEFAULT_BASE_URL}/register"
    assert metadata["registration_endpoint"] == expected_endpoint, (
        f"Expected registration endpoint '{expected_endpoint}', "
        f"got '{metadata['registration_endpoint']}'"
    )
    print(f"  Registration endpoint: {metadata['registration_endpoint']}")
    
    # Test 3: Custom Base URL
    print_test_header(3, "Custom Base URL")
    custom_provider = InMemoryOAuthProvider(base_url=CUSTOM_BASE_URL)
    custom_metadata = custom_provider.metadata
    expected_custom_endpoint = f"{CUSTOM_BASE_URL}/register"
    assert custom_metadata["registration_endpoint"] == expected_custom_endpoint, (
        f"Expected custom endpoint '{expected_custom_endpoint}', "
        f"got '{custom_metadata['registration_endpoint']}'"
    )
    print(f"  Custom base URL works correctly: {custom_metadata['registration_endpoint']}")
    
    # Test 4: Auth Methods Supported
    print_test_header(4, "Registration Endpoint Auth Methods")
    auth_methods = metadata["registration_endpoint_auth_methods_supported"]
    assert isinstance(auth_methods, list), "Auth methods must be a list"
    assert "none" in auth_methods, "Auth methods must include 'none'"
    print(f"  Auth methods: {auth_methods}")
    
    # Test 5: Registration Types Supported
    print_test_header(5, "Client Registration Types")
    registration_types = metadata["client_registration_types_supported"]
    assert isinstance(registration_types, list), "Registration types must be a list"
    assert "automatic" in registration_types, "Registration types must include 'automatic'"
    print(f"  Registration types: {registration_types}")
    
    # Test 6: Client Authentication Requirement
    print_test_header(6, "Client Authentication Requirement")
    assert metadata["require_client_authentication"] is False, (
        "Client authentication should not be required for open registration"
    )
    print(f"  Client authentication required: {metadata['require_client_authentication']}")


async def test_dynamic_client_registration():
    """Test dynamic client registration functionality."""
    print_section_header("Testing Dynamic Client Registration (DCR)")
    
    provider = InMemoryOAuthProvider()
    
    # Test 1: Basic Registration
    print_test_header(1, "Basic Dynamic Client Registration")
    registration_request = ClientRegistrationRequest(
        redirect_uris=[TEST_REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=TEST_CLIENT_NAME,
    )
    
    response = await provider.dynamic_register_client(registration_request)
    assert response.client_id is not None, "Client ID must be generated"
    assert response.client_secret is not None, "Client secret must be generated"
    assert response.client_id_issued_at > 0, "Client ID issued_at must be positive"
    assert response.redirect_uris == registration_request.redirect_uris, (
        "Redirect URIs must match request"
    )
    assert response.grant_types == registration_request.grant_types, (
        "Grant types must match request"
    )
    assert response.response_types == registration_request.response_types, (
        "Response types must match request"
    )
    print(f"  Registered client: {response.client_id}")
    print(f"  Client secret: {response.client_secret[:20]}...")
    print(f"  Issued at: {response.client_id_issued_at}")
    
    # Test 2: Minimal Fields Registration
    print_test_header(2, "Registration with Minimal Fields")
    minimal_request = ClientRegistrationRequest(
        redirect_uris=[TEST_REDIRECT_URI]
    )
    
    minimal_response = await provider.dynamic_register_client(minimal_request)
    assert minimal_response.client_id is not None, "Client ID must be generated"
    assert minimal_response.client_secret is not None, "Client secret must be generated"
    print(f"  Minimal registration successful: {minimal_response.client_id}")
    
    # Test 3: Client Storage Verification
    print_test_header(3, "Client Storage Verification")
    stored_client = await provider.get_client(response.client_id)
    assert stored_client is not None, "Client must be stored and retrievable"
    assert stored_client.client_id == response.client_id, "Stored client ID must match"
    assert stored_client.client_secret == response.client_secret, (
        "Stored client secret must match"
    )
    assert stored_client.redirect_uris == response.redirect_uris, (
        "Stored redirect URIs must match"
    )
    print("  Client correctly stored and retrievable")
    
    # Test 4: Empty Redirect URIs Validation
    print_test_header(4, "Empty Redirect URIs Validation")
    invalid_request = ClientRegistrationRequest(redirect_uris=[])
    
    try:
        await provider.dynamic_register_client(invalid_request)
        assert False, "Should have raised ValueError for empty redirect_uris"
    except ValueError as e:
        assert "redirect_uris" in str(e), (
            f"Error message should mention 'redirect_uris', got: {str(e)}"
        )
        print(f"  Empty redirect_uris correctly rejected: {str(e)}")
    
    # Test 5: Automatic Refresh Token Grant Addition
    print_test_header(5, "Automatic Refresh Token Grant Addition")
    auth_code_only_request = ClientRegistrationRequest(
        redirect_uris=[TEST_REDIRECT_URI],
        grant_types=["authorization_code"],  # Missing refresh_token
    )
    
    auth_code_response = await provider.dynamic_register_client(auth_code_only_request)
    assert "authorization_code" in auth_code_response.grant_types, (
        "Response must include authorization_code grant type"
    )
    assert "refresh_token" in auth_code_response.grant_types, (
        "Refresh token grant should be automatically added"
    )
    print("  Refresh token grant automatically added")
    print(f"  Final grant types: {auth_code_response.grant_types}")
    
    # Test 6: Full Registration with All Fields
    print_test_header(6, "Registration with All Optional Fields")
    full_request = ClientRegistrationRequest(
        redirect_uris=[TEST_REDIRECT_URI, SECOND_REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=FULL_CLIENT_NAME,
        client_uri="http://example.com",
        logo_uri="http://example.com/logo.png",
        scope="read write admin",
        contacts=["admin@example.com"],
        tos_uri="http://example.com/tos",
        policy_uri="http://example.com/policy",
        token_endpoint_auth_method="client_secret_post",
    )
    
    full_response = await provider.dynamic_register_client(full_request)
    assert full_response.client_name == FULL_CLIENT_NAME, "Client name must match"
    assert full_response.client_uri == "http://example.com", "Client URI must match"
    assert full_response.logo_uri == "http://example.com/logo.png", "Logo URI must match"
    assert full_response.scope == "read write admin", "Scope must match"
    assert full_response.contacts == ["admin@example.com"], "Contacts must match"
    assert full_response.tos_uri == "http://example.com/tos", "TOS URI must match"
    assert full_response.policy_uri == "http://example.com/policy", "Policy URI must match"
    assert full_response.token_endpoint_auth_method == "client_secret_post", (
        "Token endpoint auth method must match"
    )
    print("  All fields correctly stored:")
    print(f"    Name: {full_response.client_name}")
    print(f"    URI: {full_response.client_uri}")
    print(f"    Scope: {full_response.scope}")
    print(f"    Contacts: {full_response.contacts}")


async def test_metadata_integration():
    """Test metadata integration with client registration."""
    print_section_header("Testing Metadata Integration")
    
    # Test 1: Metadata Endpoints Match Registration
    print_test_header(1, "Metadata Endpoints Match Registration")
    provider = InMemoryOAuthProvider(base_url=DEFAULT_BASE_URL)
    metadata = provider.metadata
    
    registration_request = ClientRegistrationRequest(
        redirect_uris=[TEST_REDIRECT_URI]
    )
    
    response = await provider.dynamic_register_client(registration_request)
    assert response.client_id is not None, "Client ID must be generated"
    expected_endpoint = f"{DEFAULT_BASE_URL}/register"
    assert metadata["registration_endpoint"] == expected_endpoint, (
        f"Metadata registration endpoint must match: {expected_endpoint}"
    )
    print(f"  Metadata registration endpoint matches: {metadata['registration_endpoint']}")
    
    # Test 2: Base URL Consistency
    print_test_header(2, "Base URL Consistency")
    custom_provider = InMemoryOAuthProvider(base_url=EXAMPLE_BASE_URL)
    custom_metadata = custom_provider.metadata
    
    assert custom_metadata["registration_endpoint"].startswith(EXAMPLE_BASE_URL), (
        f"Registration endpoint must start with base URL: {EXAMPLE_BASE_URL}"
    )
    print(f"  Base URL consistent across metadata: {custom_metadata['registration_endpoint']}")


async def run_all_tests():
    """Run all metadata and DCR tests."""
    try:
        await test_oauth_metadata()
        await test_dynamic_client_registration()
        await test_metadata_integration()
        
        print_section_header("✅ All OAuth Metadata and DCR Tests Passed!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {str(e)}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(run_all_tests())
