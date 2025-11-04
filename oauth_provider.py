"""
Full OAuth 2.1 Server Implementation for FastMCP

WARNING: This is an advanced pattern requiring deep security expertise.
This implementation uses in-memory storage for demonstration purposes.
Production systems require:
- Secure database storage
- Proper cryptographic token generation
- PKCE validation
- Rate limiting
- Security monitoring
- Regular security audits
"""

import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Union
from fastmcp.server.auth import OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationParams,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
)
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthToken,
)
from pydantic import BaseModel, Field
from typing import List


class ClientRegistrationRequest(BaseModel):
    """
    OAuth 2.0 Dynamic Client Registration request (RFC 7591).
    """
    redirect_uris: List[str] = Field(..., description="Array of redirection URI strings")
    token_endpoint_auth_method: Optional[str] = Field(
        default="client_secret_basic",
        description="Authentication method for token endpoint"
    )
    grant_types: Optional[List[str]] = Field(
        default=["authorization_code"],
        description="Array of OAuth 2.0 grant types"
    )
    response_types: Optional[List[str]] = Field(
        default=["code"],
        description="Array of OAuth 2.0 response types"
    )
    client_name: Optional[str] = Field(default=None, description="Human-readable client name")
    client_uri: Optional[str] = Field(default=None, description="URL of client's home page")
    logo_uri: Optional[str] = Field(default=None, description="URL of client's logo")
    scope: Optional[str] = Field(default=None, description="Space-separated scope values")
    contacts: Optional[List[str]] = Field(default=None, description="Contact email addresses")
    tos_uri: Optional[str] = Field(default=None, description="URL of terms of service")
    policy_uri: Optional[str] = Field(default=None, description="URL of privacy policy")


class ClientRegistrationResponse(BaseModel):
    """
    OAuth 2.0 Dynamic Client Registration response (RFC 7591).
    """
    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: int
    client_secret_expires_at: int = 0  # 0 means never expires
    redirect_uris: List[str]
    token_endpoint_auth_method: str
    grant_types: List[str]
    response_types: List[str]
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: Optional[str] = None
    contacts: Optional[List[str]] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None


class InMemoryOAuthProvider(OAuthProvider):
    """
    In-memory OAuth 2.1 provider implementation.
    
    This stores all data in memory and will be lost on restart.
    For production, replace with database-backed storage.
    """
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        super().__init__(
            base_url=base_url,
            issuer_url=base_url,
            service_documentation_url=f"{base_url}/docs",
        )
        
        # In-memory storage (replace with database in production)
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.authorization_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        
        # Track revoked tokens
        self.revoked_tokens: set[str] = set()
        
        # Simple user database (for demo purposes)
        self.users: dict[str, dict] = {
            "demo_user": {
                "username": "demo_user",
                "password": "demo_password",  # In production: use bcrypt/argon2
                "scopes": ["read", "write"],
            }
        }
    
    # ===== Client Management =====
    
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """Retrieve client information by ID."""
        return self.clients.get(client_id)
    
    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Store new client registration."""
        self.clients[client_info.client_id] = client_info
    
    async def dynamic_register_client(
        self,
        registration: ClientRegistrationRequest,
    ) -> ClientRegistrationResponse:
        """
        Dynamic Client Registration (RFC 7591).
        
        Allows clients to register themselves at runtime via API.
        Generates client_id and client_secret automatically.
        """
        # Validate redirect URIs (must not be empty)
        if not registration.redirect_uris:
            raise ValueError("redirect_uris is required and must not be empty")
        
        # Validate grant types and response types consistency
        grant_types = registration.grant_types or ["authorization_code"]
        response_types = registration.response_types or ["code"]
        
        # Ensure authorization_code grant has refresh_token if needed
        if "authorization_code" in grant_types and "refresh_token" not in grant_types:
            grant_types.append("refresh_token")
        
        # Generate client credentials
        client_id = f"dcr_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        
        # Create client info
        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=registration.redirect_uris,
            grant_types=grant_types,
            response_types=response_types,
            scope=registration.scope or "read",
            token_endpoint_auth_method=registration.token_endpoint_auth_method or "client_secret_basic",
            registration_endpoint=self.base_url + "/register",
        )
        
        # Store the client
        await self.register_client(client_info)
        
        # Create response following RFC 7591
        issued_at = int(time.time())
        
        return ClientRegistrationResponse(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=issued_at,
            client_secret_expires_at=0,  # Never expires
            redirect_uris=registration.redirect_uris,
            token_endpoint_auth_method=client_info.token_endpoint_auth_method,
            grant_types=grant_types,
            response_types=response_types,
            client_name=registration.client_name,
            client_uri=registration.client_uri,
            logo_uri=registration.logo_uri,
            scope=registration.scope,
            contacts=registration.contacts,
            tos_uri=registration.tos_uri,
            policy_uri=registration.policy_uri,
        )
    
    # ===== Authorization Flow =====
    
    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """
        Handle authorization request.
        
        In a real implementation, this would:
        1. Show a login page if user not authenticated
        2. Show a consent page for scope approval
        3. Validate PKCE challenge
        4. Generate authorization code
        5. Redirect back to client
        
        This demo implementation auto-approves for the demo user.
        """
        # Validate redirect URI
        if params.redirect_uri not in client.redirect_uris:
            raise ValueError(f"Invalid redirect_uri: {params.redirect_uri}")
        
        # In production: authenticate user and get consent
        # For demo: auto-approve with demo user
        user_id = "demo_user"
        
        # Generate authorization code
        code = secrets.token_urlsafe(32)
        
        # Store authorization code with PKCE challenge
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            scope=params.scope or [],
            code_challenge=params.code_challenge,
            code_challenge_method=params.code_challenge_method,
            expires_at=datetime.now() + timedelta(minutes=10),
            user_id=user_id,  # Associate with user
        )
        
        self.authorization_codes[code] = auth_code
        
        # Build redirect URL with code and state
        redirect_url = f"{params.redirect_uri}?code={code}"
        if params.state:
            redirect_url += f"&state={params.state}"
        
        return redirect_url
    
    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> Optional[AuthorizationCode]:
        """Load and validate authorization code."""
        auth_code = self.authorization_codes.get(authorization_code)
        
        if not auth_code:
            return None
        
        # Validate client matches
        if auth_code.client_id != client.client_id:
            return None
        
        # Check expiration
        if datetime.now() > auth_code.expires_at:
            # Clean up expired code
            del self.authorization_codes[authorization_code]
            return None
        
        return auth_code
    
    # ===== Token Management =====
    
    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        # Generate tokens
        access_token_str = secrets.token_urlsafe(32)
        refresh_token_str = secrets.token_urlsafe(32)
        
        # Create access token
        access_token = AccessToken(
            token=access_token_str,
            client_id=client.client_id,
            scope=authorization_code.scope,
            expires_at=datetime.now() + timedelta(hours=1),
            user_id=authorization_code.user_id,
        )
        
        # Create refresh token
        refresh_token = RefreshToken(
            token=refresh_token_str,
            client_id=client.client_id,
            scope=authorization_code.scope,
            expires_at=datetime.now() + timedelta(days=30),
            user_id=authorization_code.user_id,
        )
        
        # Store tokens
        self.access_tokens[access_token_str] = access_token
        self.refresh_tokens[refresh_token_str] = refresh_token
        
        # Delete used authorization code (one-time use)
        del self.authorization_codes[authorization_code.code]
        
        # Return OAuth token response
        return OAuthToken(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=3600,  # 1 hour
            refresh_token=refresh_token_str,
            scope=authorization_code.scope,
        )
    
    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> Optional[RefreshToken]:
        """Load and validate refresh token."""
        token = self.refresh_tokens.get(refresh_token)
        
        if not token:
            return None
        
        # Check if revoked
        if refresh_token in self.revoked_tokens:
            return None
        
        # Validate client matches
        if token.client_id != client.client_id:
            return None
        
        # Check expiration
        if datetime.now() > token.expires_at:
            del self.refresh_tokens[refresh_token]
            return None
        
        return token
    
    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token for new access token."""
        # Validate requested scopes are subset of original
        if not set(scopes).issubset(set(refresh_token.scope)):
            raise ValueError("Requested scopes exceed original grant")
        
        # Generate new access token
        access_token_str = secrets.token_urlsafe(32)
        
        access_token = AccessToken(
            token=access_token_str,
            client_id=client.client_id,
            scope=scopes,
            expires_at=datetime.now() + timedelta(hours=1),
            user_id=refresh_token.user_id,
        )
        
        # Store new access token
        self.access_tokens[access_token_str] = access_token
        
        # Optionally rotate refresh token (recommended)
        new_refresh_token_str = secrets.token_urlsafe(32)
        new_refresh_token = RefreshToken(
            token=new_refresh_token_str,
            client_id=client.client_id,
            scope=refresh_token.scope,
            expires_at=datetime.now() + timedelta(days=30),
            user_id=refresh_token.user_id,
        )
        
        # Store new refresh token and revoke old one
        self.refresh_tokens[new_refresh_token_str] = new_refresh_token
        self.revoked_tokens.add(refresh_token.token)
        
        return OAuthToken(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=new_refresh_token_str,
            scope=scopes,
        )
    
    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        """Load access token by token string."""
        access_token = self.access_tokens.get(token)
        
        if not access_token:
            return None
        
        # Check if revoked
        if token in self.revoked_tokens:
            return None
        
        # Check expiration
        if datetime.now() > access_token.expires_at:
            del self.access_tokens[token]
            return None
        
        return access_token
    
    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """Revoke a token."""
        self.revoked_tokens.add(token.token)
        
        # Remove from storage
        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)
        elif isinstance(token, RefreshToken):
            self.refresh_tokens.pop(token.token, None)
    
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify bearer token for incoming requests.
        
        This is called on every authenticated request to validate
        the access token provided in the Authorization header.
        """
        return await self.load_access_token(token)
    
    # ===== Helper Methods =====
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens from storage (call periodically)."""
        now = datetime.now()
        
        # Clean authorization codes
        self.authorization_codes = {
            k: v for k, v in self.authorization_codes.items()
            if v.expires_at > now
        }
        
        # Clean access tokens
        self.access_tokens = {
            k: v for k, v in self.access_tokens.items()
            if v.expires_at > now
        }
        
        # Clean refresh tokens
        self.refresh_tokens = {
            k: v for k, v in self.refresh_tokens.items()
            if v.expires_at > now
        }
    
    # Override metadata generation to include DCR support
    @property
    def metadata(self) -> dict:
        """Override to provide custom OAuth metadata with DCR support."""
        # Get base metadata if available
        base_metadata = super().metadata if hasattr(super(), 'metadata') else {}
        
        # Add/override with our custom metadata
        return {
            **base_metadata,
            "registration_endpoint": f"{self.base_url}/register",
            "registration_endpoint_auth_methods_supported": ["none"],
            "client_registration_types_supported": ["automatic"],
            "require_client_authentication": False,  # Allow open registration
        }

