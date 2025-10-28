# OAuth MCP Server

A complete OAuth 2.1 server implementation for FastMCP with PKCE support.

## ⚠️ Security Warning

**This is an advanced authentication pattern.** Building a secure OAuth server requires deep expertise in authentication protocols, cryptography, and security best practices. The FastMCP documentation strongly recommends using Remote OAuth or OAuth Proxy instead unless you have compelling requirements.

See [OAUTH_README.md](./OAUTH_README.md) for complete documentation.

## Quick Start

### Installation

```bash
# Install dependencies
uv sync
```

### Run the Server

```bash
python main.py
```

The server will start on `http://localhost:8000` with a demo OAuth client registered.

### Test the OAuth Flow

In a separate terminal:

```bash
python oauth_client_example.py
```

This will demonstrate the complete OAuth 2.1 flow including:
- PKCE challenge/verifier generation
- Authorization code exchange
- Access token usage
- Token refresh

### Test Dynamic Client Registration

Register new OAuth clients dynamically at runtime:

```bash
python test_dcr.py
```

Or use curl:

```bash
curl -X POST http://localhost:8000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:5000/callback"],
    "client_name": "My App",
    "scope": "read write"
  }'
```

The server will respond with a `client_id` and `client_secret` that you can use immediately.

### Test New OAuth Endpoints

Test all the new OAuth 2.0/2.1 endpoints:

```bash
python test_new_endpoints.py
```

This tests:
- OAuth Authorization Server Metadata discovery
- Token revocation (RFC 7009)
- Token introspection (RFC 7662)
- UserInfo endpoint

## Demo Credentials

**OAuth Client:**
- Client ID: `demo_client`
- Client Secret: `demo_secret`

**Demo User:**
- Username: `demo_user`
- Password: `demo_password`

## Project Structure

```
oauth_mcp/
├── main.py                      # FastMCP server with OAuth
├── oauth_provider.py            # OAuth 2.1 server implementation
├── oauth_client_example.py      # Complete OAuth flow demo
├── test_dcr.py                  # Dynamic Client Registration test
├── test_new_endpoints.py        # Tests for all new OAuth endpoints
├── client.py                    # Original simple client (no auth)
├── OAUTH_README.md             # Complete documentation
└── README.md                   # This file
```

## Features

✅ Full OAuth 2.1 implementation  
✅ PKCE (Proof Key for Code Exchange)  
✅ Authorization code flow  
✅ Token refresh with rotation  
✅ Token revocation (RFC 7009)  
✅ Token introspection (RFC 7662)  
✅ Scope validation  
✅ State parameter for CSRF protection  
✅ Dynamic Client Registration (DCR) - RFC 7591  
✅ OAuth Authorization Server Metadata (RFC 8414)  
✅ OAuth Protected Resource Metadata (RFC 9470)  
✅ UserInfo endpoint for user profile  

## Documentation

See [OAUTH_README.md](./OAUTH_README.md) for:
- Detailed architecture
- Security considerations
- Production deployment guide
- Database schema
- Testing strategies
- Troubleshooting

## References

- [FastMCP OAuth Documentation](https://gofastmcp.com/servers/auth/full-oauth-server)
- [OAuth 2.1 Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [PKCE Specification (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)
- [Dynamic Client Registration (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)

## License

Copyright Anysphere Inc.

