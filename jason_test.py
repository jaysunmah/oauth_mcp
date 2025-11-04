#!/usr/bin/env python3
"""
Test OAuth Provider Metadata Property

This test verifies that the OAuth provider's metadata property
correctly includes dynamic client registration (DCR) support
and returns properly formatted OAuth metadata.
"""

try:
    import pytest
except ImportError:
    pytest = None

from oauth_provider import InMemoryOAuthProvider


def test_metadata_property_basic():
    """Test that metadata property returns a dictionary."""
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    metadata = provider.metadata
    
    assert isinstance(metadata, dict), "Metadata should return a dictionary"
    assert len(metadata) > 0, "Metadata should not be empty"


def test_metadata_includes_registration_endpoint():
    """Test that metadata includes registration endpoint."""
    base_url = "http://localhost:8000"
    provider = InMemoryOAuthProvider(base_url=base_url)
    metadata = provider.metadata
    
    assert "registration_endpoint" in metadata, "Metadata should include registration_endpoint"
    assert metadata["registration_endpoint"] == f"{base_url}/register", \
        "Registration endpoint should match base URL"


def test_metadata_includes_dcr_support():
    """Test that metadata includes DCR (Dynamic Client Registration) support fields."""
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    metadata = provider.metadata
    
    assert "registration_endpoint_auth_methods_supported" in metadata, \
        "Metadata should include registration_endpoint_auth_methods_supported"
    assert metadata["registration_endpoint_auth_methods_supported"] == ["none"], \
        "Registration endpoint should support 'none' auth method"
    
    assert "client_registration_types_supported" in metadata, \
        "Metadata should include client_registration_types_supported"
    assert "automatic" in metadata["client_registration_types_supported"], \
        "Should support automatic client registration"


def test_metadata_different_base_urls():
    """Test that metadata correctly uses different base URLs."""
    test_urls = [
        "http://localhost:8000",
        "https://example.com",
        "https://api.example.com:8443",
    ]
    
    for base_url in test_urls:
        provider = InMemoryOAuthProvider(base_url=base_url)
        metadata = provider.metadata
        
        assert metadata["registration_endpoint"] == f"{base_url}/register", \
            f"Registration endpoint should match {base_url}"


def test_metadata_requires_no_authentication():
    """Test that metadata indicates open registration."""
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    metadata = provider.metadata
    
    assert "require_client_authentication" in metadata, \
        "Metadata should include require_client_authentication"
    assert metadata["require_client_authentication"] is False, \
        "Should allow open registration (no client authentication required)"


def test_metadata_base_metadata_merging():
    """Test that base metadata is properly merged with custom metadata."""
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    metadata = provider.metadata
    
    # Custom fields should be present
    assert "registration_endpoint" in metadata
    assert "registration_endpoint_auth_methods_supported" in metadata
    assert "client_registration_types_supported" in metadata
    
    # Custom fields should override any base metadata
    assert metadata["registration_endpoint"] == "http://localhost:8000/register"


def test_metadata_property_idempotent():
    """Test that calling metadata property multiple times returns consistent results."""
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    
    metadata1 = provider.metadata
    metadata2 = provider.metadata
    metadata3 = provider.metadata
    
    assert metadata1 == metadata2 == metadata3, \
        "Metadata property should be idempotent"


if __name__ == "__main__":
    # Run tests directly if pytest is not available
    print("="*60)
    print("Testing OAuth Provider Metadata Property")
    print("="*60)
    
    provider = InMemoryOAuthProvider(base_url="http://localhost:8000")
    
    print("\n✓ Test 1: Metadata returns dictionary")
    metadata = provider.metadata
    assert isinstance(metadata, dict)
    print(f"   Metadata keys: {list(metadata.keys())[:5]}...")
    
    print("\n✓ Test 2: Registration endpoint included")
    assert "registration_endpoint" in metadata
    print(f"   Registration endpoint: {metadata['registration_endpoint']}")
    
    print("\n✓ Test 3: DCR support fields included")
    assert "registration_endpoint_auth_methods_supported" in metadata
    assert "client_registration_types_supported" in metadata
    print(f"   Auth methods: {metadata['registration_endpoint_auth_methods_supported']}")
    print(f"   Registration types: {metadata['client_registration_types_supported']}")
    
    print("\n✓ Test 4: Different base URLs")
    test_urls = ["http://localhost:8000", "https://example.com"]
    for url in test_urls:
        p = InMemoryOAuthProvider(base_url=url)
        m = p.metadata
        assert m["registration_endpoint"] == f"{url}/register"
    print("   All base URLs handled correctly")
    
    print("\n✓ Test 5: Open registration")
    assert metadata.get("require_client_authentication") is False
    print("   Open registration (no auth required) confirmed")
    
    print("\n✓ Test 6: Idempotent property")
    m1 = provider.metadata
    m2 = provider.metadata
    assert m1 == m2
    print("   Property is idempotent")
    
    print("\n" + "="*60)
    print("✅ All tests passed!")
    print("="*60)
