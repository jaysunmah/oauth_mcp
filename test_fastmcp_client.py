#!/usr/bin/env python3
"""
Test FastMCP Client with OAuth

This script tests the MCP server using FastMCP's built-in client
with OAuth authentication support.
"""

import asyncio
import os
from fastmcp import Client


async def test_with_demo_client():
    """Test using pre-registered demo client credentials."""
    print("\n" + "="*60)
    print("🧪 FastMCP Client Test with OAuth")
    print("="*60)
    
    # Set OAuth credentials as environment variables
    os.environ["OAUTH_CLIENT_ID"] = "demo_client"
    os.environ["OAUTH_CLIENT_SECRET"] = "demo_secret"
    
    # Create client pointing to MCP endpoint (HTTP transport)
    client = Client("http://localhost:8000/mcp")
    
    print("\n📡 Connecting to MCP server with OAuth...")
    print(f"   MCP Endpoint: http://localhost:8000/mcp")
    print(f"   Client ID: {os.environ['OAUTH_CLIENT_ID']}")
    
    try:
        async with client:
            print("   ✅ Connected successfully!")
            
            # List available tools
            print("\n🔧 Available tools:")
            tools = await client.get_available_tools()
            for tool in tools:
                print(f"   - {tool.name}: {tool.description}")
            
            # Test greet tool
            print("\n📞 Testing greet tool...")
            result = await client.call_tool("greet", {"name": "OAuth User"})
            print(f"   Result: {result.content[0].text}")
            
            # Test get_secret tool
            print("\n🔐 Testing get_secret tool...")
            result = await client.call_tool("get_secret", {"key": "api_key"})
            print(f"   Result: {result.content[0].text}")
            
            # Test with invalid key
            print("\n🔐 Testing get_secret with invalid key...")
            result = await client.call_tool("get_secret", {"key": "nonexistent"})
            print(f"   Result: {result.content[0].text}")
            
            print("\n✅ All tests completed successfully!")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


async def test_without_credentials():
    """Test without credentials (should fail)."""
    print("\n" + "="*60)
    print("🧪 FastMCP Client Test without Credentials")
    print("="*60)
    
    # Clear any existing OAuth environment variables
    os.environ.pop("OAUTH_CLIENT_ID", None)
    os.environ.pop("OAUTH_CLIENT_SECRET", None)
    
    # Create client without credentials
    client = Client("http://localhost:8000/mcp")
    
    print("\n📡 Attempting to connect without credentials...")
    print(f"   MCP Endpoint: http://localhost:8000/mcp")
    
    try:
        async with client:
            print("   ❌ Should not have connected without auth!")
            
    except Exception as e:
        print(f"   ✅ Expected error (no auth): {str(e)[:100]}...")
        # This is expected behavior - server requires OAuth


async def main():
    """Run all tests."""
    print("\n🚀 Testing FastMCP Client with OAuth MCP Server")
    print("="*60)
    print("Server URL: http://localhost:8000")
    print("="*60)
    
    # Check if server is running
    try:
        import httpx
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get("http://localhost:8000/.well-known/openid-configuration")
            if response.status_code == 200:
                print("✅ MCP OAuth server is running")
            else:
                print("❌ Server responded but OAuth metadata not found")
                return
    except Exception as e:
        print("❌ MCP server is not running! Please start it first.")
        print(f"   Error: {str(e)}")
        return
    
    # Test 1: Use demo client credentials
    await test_with_demo_client()
    
    # Test 2: Try without credentials (should fail)
    print("\n⏳ Waiting 2 seconds before next test...")
    await asyncio.sleep(2)
    
    await test_without_credentials()
    
    print("\n" + "="*60)
    print("🎉 All tests completed!")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
