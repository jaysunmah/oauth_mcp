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
├── client.py                    # Original simple client (no auth)
├── OAUTH_README.md             # Complete documentation
└── README.md                   # This file
```

## Features

✅ Full OAuth 2.1 implementation  
✅ PKCE (Proof Key for Code Exchange)  
✅ Authorization code flow  
✅ Token refresh with rotation  
✅ Token revocation  
✅ Scope validation  
✅ State parameter for CSRF protection  

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
- [PKCE Specification](https://datatracker.ietf.org/doc/html/rfc7636)

## License

Copyright Anysphere Inc.

