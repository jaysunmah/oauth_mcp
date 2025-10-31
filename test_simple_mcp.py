#!/usr/bin/env python3
"""
Simple test to check MCP server endpoints and OAuth flow
"""

import asyncio
import httpx
import json
import os


async def test_mcp_directly():
    """Test MCP server directly with manual OAuth flow."""
    print("\n🧪 Testing MCP Server with Manual OAuth")
    print("="*60)
    
    # Use demo credentials
    client_id = "demo_client"
    client_secret = "demo_secret"
    
    # First, let's check if we can access the MCP endpoint without auth
    print("\n1️⃣ Testing /mcp endpoint without auth...")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                "http://localhost:8000/mcp",
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
            print(f"   Response status: {response.status_code}")
            print(f"   Response body: {response.text[:200]}...")
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    # Try the /mcp/connect endpoint mentioned in the server
    print("\n2️⃣ Testing /mcp/connect endpoint...")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("http://localhost:8000/mcp/connect")
            print(f"   Response status: {response.status_code}")
            if response.status_code == 401:
                data = response.json()
                print(f"   OAuth metadata URL: {data.get('oauth_metadata_url', 'N/A')}")
                print(f"   Registration endpoint: {data.get('registration_endpoint', 'N/A')}")
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    # Let's try to get an access token using client credentials
    print("\n3️⃣ Attempting to get access token with client credentials...")
    async with httpx.AsyncClient() as client:
        try:
            # Try client credentials grant
            response = await client.post(
                "http://localhost:8000/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "read write"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            print(f"   Response status: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    # Let's check what OAuth flow the server supports
    print("\n4️⃣ Checking supported OAuth flows...")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get("http://localhost:8000/.well-known/openid-configuration")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   Grant types: {metadata.get('grant_types_supported', [])}")
                print(f"   Response types: {metadata.get('response_types_supported', [])}")
                print(f"   Token endpoint: {metadata.get('token_endpoint', 'N/A')}")
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    # Try setting OAuth credentials as headers
    print("\n5️⃣ Testing MCP with Bearer token (if we had one)...")
    print("   Note: The server uses authorization_code flow, not client_credentials")
    print("   A full OAuth flow with user authorization is required")
    
    # Test basic tools endpoint
    print("\n6️⃣ Testing if tools endpoint requires auth...")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get("http://localhost:8000/tools")
            print(f"   GET /tools status: {response.status_code}")
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    print("\n" + "="*60)
    print("Summary: The server requires OAuth authorization_code flow.")
    print("FastMCP's client needs to handle the full OAuth flow.")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(test_mcp_directly())
