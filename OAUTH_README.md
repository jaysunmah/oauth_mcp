# OAuth 2.1 Full Server Implementation for FastMCP

This project implements a complete OAuth 2.1 server for FastMCP, following the pattern documented at https://gofastmcp.com/servers/auth/full-oauth-server

## ⚠️ Important Security Warning

**This is an extremely advanced pattern that requires deep security expertise.** The FastMCP documentation strongly recommends against implementing your own OAuth server unless you have:

- Deep expertise in authentication protocols and cryptography
- Security monitoring and incident response capabilities
- Compliance and audit requirements
- A compelling reason external identity providers cannot meet

**For most use cases, use Remote OAuth or OAuth Proxy instead.**

## Architecture

### Components

1. **`oauth_provider.py`** - Full OAuth 2.1 server implementation
   - Extends `OAuthProvider` from FastMCP
   - Implements all required abstract methods
   - Uses in-memory storage (replace with database for production)

2. **`main.py`** - FastMCP server with OAuth authentication
   - Registers demo OAuth client on startup
   - Defines authenticated tools
   - Runs the MCP server with OAuth enabled

3. **`oauth_client_example.py`** - Complete OAuth flow demonstration
   - Shows PKCE implementation
   - Demonstrates authorization code flow
   - Handles token refresh

## OAuth 2.1 Flow

```
┌─────────┐                                  ┌─────────┐
│         │                                  │         │
│  Client │                                  │  Server │
│         │                                  │         │
└────┬────┘                                  └────┬────┘
     │                                            │
     │  1. Request Authorization URL              │
     │    (with PKCE challenge)                   │
     │───────────────────────────────────────────>│
     │                                            │
     │  2. User visits URL, logs in, approves     │
     │                                            │
     │  3. Redirect with authorization code       │
     │<───────────────────────────────────────────│
     │                                            │
     │  4. Exchange code for token                │
     │    (with PKCE verifier)                    │
     │───────────────────────────────────────────>│
     │                                            │
     │  5. Return access + refresh tokens         │
     │<───────────────────────────────────────────│
     │                                            │
     │  6. Call tools with Bearer token           │
     │───────────────────────────────────────────>│
     │                                            │
     │  7. When expired, refresh token            │
     │───────────────────────────────────────────>│
     │                                            │
     │  8. New access + refresh tokens            │
     │<───────────────────────────────────────────│
     │                                            │
```

## Implementation Details

### Required Abstract Methods

The `InMemoryOAuthProvider` implements all 10 required methods:

#### Client Management
- `get_client()` - Retrieve OAuth client by ID
- `register_client()` - Store new OAuth client

#### Authorization Flow
- `authorize()` - Handle authorization request, show login/consent
- `load_authorization_code()` - Validate and load authorization code

#### Token Management
- `exchange_authorization_code()` - Exchange code for tokens
- `load_refresh_token()` - Validate and load refresh token
- `exchange_refresh_token()` - Exchange refresh for new access token
- `load_access_token()` - Load access token for verification
- `revoke_token()` - Mark token as revoked
- `verify_token()` - Verify bearer token on each request

### Security Features Implemented

✅ **PKCE (RFC 7636)** - Proof Key for Code Exchange
  - Code verifier/challenge generation
  - SHA-256 challenge method
  - Protection against authorization code interception

✅ **Token Expiration**
  - Access tokens: 1 hour
  - Refresh tokens: 30 days
  - Authorization codes: 10 minutes

✅ **Token Revocation**
  - Tracks revoked tokens
  - Prevents reuse of revoked tokens
  - Automatic cleanup of expired tokens

✅ **State Parameter**
  - CSRF protection for authorization requests
  - State validation on callback

✅ **Refresh Token Rotation**
  - New refresh token issued on each refresh
  - Old refresh token automatically revoked
  - Prevents token replay attacks

✅ **Client Validation**
  - Client ID/secret verification
  - Redirect URI validation
  - Scope validation

### Storage

**Current Implementation:** In-memory storage
- All data lost on server restart
- Suitable for development/testing only

**Production Requirements:**
- PostgreSQL, MySQL, or MongoDB for token/client storage
- Redis for short-lived authorization codes
- Encrypted storage for sensitive data
- Regular cleanup of expired tokens

## Usage

### 1. Start the Server

```bash
python main.py
```

This will:
- Register a demo OAuth client
- Start the FastMCP server on http://localhost:8000
- Print demo credentials

### 2. Demo Credentials

**OAuth Client:**
- Client ID: `demo_client`
- Client Secret: `demo_secret`
- Redirect URI: `http://localhost:3000/callback`

**Demo User:**
- Username: `demo_user`
- Password: `demo_password`
- Scopes: `["read", "write"]`

### 3. Run OAuth Flow Demo

In a new terminal:

```bash
python oauth_client_example.py
```

This demonstrates:
1. PKCE code generation
2. Authorization URL construction
3. Authorization code exchange
4. Authenticated tool calls
5. Token refresh

### 4. Manual Testing

You can also test manually using curl:

#### Get Authorization Code
```bash
# Visit this URL in a browser (or curl with -L to follow redirects)
curl -L "http://localhost:8000/oauth/authorize?response_type=code&client_id=demo_client&redirect_uri=http://localhost:3000/callback&code_challenge=YOUR_CHALLENGE&code_challenge_method=S256"
```

#### Exchange Code for Token
```bash
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=demo_client" \
  -d "client_secret=demo_secret" \
  -d "code_verifier=YOUR_VERIFIER"
```

#### Call Authenticated Tool
```bash
curl -X POST http://localhost:8000/tools/greet \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "World"}'
```

#### Refresh Token
```bash
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=demo_client" \
  -d "client_secret=demo_secret"
```

## Production Considerations

### 🔒 Security Hardening

1. **Database Storage**
   - Replace in-memory storage with PostgreSQL/MySQL
   - Use connection pooling
   - Enable encryption at rest

2. **Password Security**
   - Use bcrypt or argon2 for password hashing
   - Implement password complexity requirements
   - Add rate limiting on login attempts

3. **Token Security**
   - Use cryptographically secure random token generation
   - Consider JWT tokens with RSA/ECDSA signing
   - Implement token binding to client

4. **HTTPS Only**
   - Enforce HTTPS in production
   - Use HSTS headers
   - Proper TLS certificate management

5. **Rate Limiting**
   - Limit token endpoint requests
   - Prevent brute force attacks
   - Implement exponential backoff

6. **Logging & Monitoring**
   - Log all authentication events
   - Monitor for suspicious patterns
   - Alert on security incidents

7. **Scope Management**
   - Implement fine-grained scopes
   - Validate scopes on every request
   - Allow scope-based access control

8. **User Consent**
   - Implement proper consent UI
   - Store user consent decisions
   - Allow users to revoke access

### 📊 Database Schema Example

```sql
-- OAuth Clients
CREATE TABLE oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret_hash VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types VARCHAR(100)[] NOT NULL,
    response_types VARCHAR(100)[] NOT NULL,
    scope VARCHAR(255)[] NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Authorization Codes
CREATE TABLE authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
    user_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope VARCHAR(255)[] NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Access Tokens
CREATE TABLE access_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
    user_id VARCHAR(255) NOT NULL,
    scope VARCHAR(255)[] NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Refresh Tokens
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
    user_id VARCHAR(255) NOT NULL,
    scope VARCHAR(255)[] NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_auth_codes_expires ON authorization_codes(expires_at);
CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
```

## Testing

### Unit Tests
Create tests for each OAuth method:
- Client registration and retrieval
- Authorization code generation and validation
- Token exchange and refresh
- Token revocation
- Scope validation

### Integration Tests
Test the complete OAuth flow:
- Authorization code flow with PKCE
- Token refresh flow
- Error cases (invalid codes, expired tokens, etc.)
- Scope restrictions

### Security Tests
- PKCE validation
- State parameter validation
- Redirect URI validation
- Token replay prevention
- Scope escalation prevention

## Common Issues

### "Invalid redirect_uri"
Make sure the redirect URI in the authorization request exactly matches one of the registered redirect URIs for the client.

### "Invalid code_verifier"
The code verifier sent in the token exchange must match the code challenge used in the authorization request (SHA-256 hash).

### "Token expired"
Access tokens expire after 1 hour. Use the refresh token to get a new access token.

### "Invalid client"
Client ID and secret must match the registered client credentials.

## New Endpoints (Recently Added)

### OAuth 2.0 Authorization Server Metadata (RFC 8414)

**Endpoint:** `GET /.well-known/oauth-authorization-server`

Provides clients with OAuth server configuration for automatic discovery:

```bash
curl http://localhost:8000/.well-known/oauth-authorization-server
```

Returns metadata including all supported endpoints, grant types, and authentication methods.

### Token Revocation (RFC 7009)

**Endpoint:** `POST /oauth/revoke`

Allows clients to revoke access or refresh tokens:

```bash
# Using Basic auth
curl -X POST http://localhost:8000/oauth/revoke \
  -u "demo_client:demo_secret" \
  -d "token=YOUR_TOKEN&token_type_hint=access_token"

# Using form data
curl -X POST http://localhost:8000/oauth/revoke \
  -d "token=YOUR_TOKEN" \
  -d "client_id=demo_client" \
  -d "client_secret=demo_secret"
```

### Token Introspection (RFC 7662)

**Endpoint:** `POST /oauth/introspect`

Allows resource servers to validate tokens and get metadata:

```bash
curl -X POST http://localhost:8000/oauth/introspect \
  -u "demo_client:demo_secret" \
  -d "token=YOUR_TOKEN&token_type_hint=access_token"
```

Returns token status and metadata:
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "demo_client",
  "username": "demo_user",
  "exp": 1735432800
}
```

### UserInfo Endpoint

**Endpoint:** `GET /userinfo`

Returns authenticated user's profile information:

```bash
curl http://localhost:8000/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Returns user profile based on token scopes:
```json
{
  "sub": "demo_user",
  "name": "demo_user",
  "preferred_username": "demo_user",
  "email": "demo_user@example.com",
  "scope": "read write profile email"
}
```

## References

- FastMCP OAuth Documentation: https://gofastmcp.com/servers/auth/full-oauth-server
- OAuth 2.1 Specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
- PKCE Specification (RFC 7636): https://datatracker.ietf.org/doc/html/rfc7636
- Dynamic Client Registration (RFC 7591): https://datatracker.ietf.org/doc/html/rfc7591
- OAuth 2.0 Authorization Server Metadata (RFC 8414): https://datatracker.ietf.org/doc/html/rfc8414
- OAuth 2.0 Token Revocation (RFC 7009): https://datatracker.ietf.org/doc/html/rfc7009
- OAuth 2.0 Token Introspection (RFC 7662): https://datatracker.ietf.org/doc/html/rfc7662
- OAuth 2.0 Protected Resource Metadata (RFC 9470): https://datatracker.ietf.org/doc/html/rfc9470
- OAuth 2.0 Security Best Practices: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics

## License

Copyright Anysphere Inc.

