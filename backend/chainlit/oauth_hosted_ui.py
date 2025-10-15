"""
OAuth Hosted UI flow for Cognito authentication.
Provides browser-based login flow instead of username/password auth.
"""

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse

import httpx


@dataclass
class TokenData:
    """Stores OAuth tokens with expiry information"""

    id_token: str
    access_token: str
    refresh_token: Optional[str] = None
    id_token_expires_at: float = 0.0  # Unix timestamp
    access_token_expires_at: float = 0.0  # Unix timestamp
    discovery_url: str = ""
    client_id: str = ""
    client_secret: Optional[str] = None
    session_id: str = ""

    def time_until_id_token_expiry(self) -> float:
        """Returns seconds until ID token expires"""
        return max(0.0, self.id_token_expires_at - time.time())

    def time_until_access_token_expiry(self) -> float:
        """Returns seconds until access token expires"""
        return max(0.0, self.access_token_expires_at - time.time())

    def needs_refresh(self) -> bool:
        """
        Check if token needs refresh.

        Uses OAUTH_REFRESH_THRESHOLD_SECONDS environment variable if set,
        otherwise defaults to 600 seconds (10 minutes).

        Returns:
            True if token should be refreshed
        """
        # Get refresh threshold from environment, default to 10 minutes
        threshold = int(os.environ.get("OAUTH_REFRESH_THRESHOLD_SECONDS", "600"))
        time_until_expiry = self.time_until_id_token_expiry()
        return 0 < time_until_expiry < threshold


def decode_jwt_without_validation(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT token without signature validation (for extracting exp claim).

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict or None if decode fails
    """
    try:
        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload (add padding if needed)
        payload_encoded = parts[1]
        # Add padding for base64 decoding
        padding = 4 - (len(payload_encoded) % 4)
        if padding != 4:
            payload_encoded += "=" * padding

        payload_bytes = base64.urlsafe_b64decode(payload_encoded)
        payload = json.loads(payload_bytes.decode("utf-8"))

        return payload
    except Exception as e:
        print(f"⚠️  Failed to decode JWT: {e}")
        return None


class HostedUIProvider:
    """Provides OAuth tokens using Cognito Hosted UI flow"""

    # Store state and code verifier for PKCE
    _auth_states: Dict[str, Dict[str, str]] = {}

    # Token store for managing refresh
    _token_store: Dict[str, TokenData] = {}

    @staticmethod
    def generate_pkce_pair() -> tuple[str, str]:
        """
        Generate PKCE code verifier and code challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate code verifier (43-128 characters)
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )

        # Generate code challenge (SHA256 of verifier)
        code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )

        return code_verifier, code_challenge

    @classmethod
    def get_authorization_url(
        cls,
        discovery_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid email profile offline_access",
    ) -> tuple[str, str]:
        """
        Generate the Cognito Hosted UI authorization URL.

        Args:
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            redirect_uri: Where to redirect after login
            scope: OAuth scopes to request

        Returns:
            Tuple of (authorization_url, state)
        """
        # Fetch the discovery document to get the correct authorization endpoint
        try:
            import httpx

            response = httpx.get(discovery_url, timeout=10.0)
            response.raise_for_status()
            discovery_doc = response.json()

            # Extract the authorization endpoint from discovery document
            authorization_endpoint = discovery_doc.get("authorization_endpoint")
            if not authorization_endpoint:
                raise ValueError(
                    "authorization_endpoint not found in discovery document"
                )

            print("🔍 Fetched OAuth configuration from discovery endpoint")
            print(f"   Discovery URL: {discovery_url}")
            print(f"   Authorization Endpoint: {authorization_endpoint}")

        except Exception as e:
            print(f"⚠️  Failed to fetch discovery document: {e}")
            # Fallback to environment variable or error
            cognito_domain = os.getenv("COGNITO_DOMAIN")
            if cognito_domain:
                print(f"   Using COGNITO_DOMAIN from environment: {cognito_domain}")
                authorization_endpoint = f"https://{cognito_domain}/oauth2/authorize"
            else:
                raise ValueError(
                    f"Failed to fetch discovery document and COGNITO_DOMAIN not set: {e}"
                )

        # Generate state and PKCE parameters
        state = secrets.token_urlsafe(32)
        code_verifier, code_challenge = cls.generate_pkce_pair()

        # Store for later verification
        cls._auth_states[state] = {
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "discovery_url": discovery_url,
            "client_id": client_id,
            "authorization_endpoint": authorization_endpoint,
        }

        # Build authorization URL using the correct endpoint
        params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{authorization_endpoint}?{urlencode(params)}"

        # Extract domain for logging
        parsed_url = urlparse(authorization_endpoint)
        domain = parsed_url.netloc

        print("🔐 Generated Hosted UI authorization URL")
        print(f"   Domain: {domain}")
        print(f"   Client ID: {client_id}")
        print(f"   Redirect URI: {redirect_uri}")
        print(f"   Scope: {scope}")
        print(f"   State: {state[:16]}...")
        print(f"   Code Challenge: {code_challenge[:20]}...")
        print("   Code Challenge Method: S256")
        print(f"   Full URL: {auth_url}")

        return auth_url, state

    @classmethod
    async def exchange_code_for_token(
        cls,
        discovery_url: str,
        client_id: str,
        authorization_code: str,
        state: str,
        client_secret: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for tokens.

        Args:
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            authorization_code: Code from callback
            state: State parameter for verification
            client_secret: Optional client secret for confidential clients

        Returns:
            Token response dict or None
        """
        try:
            # Verify state and get stored parameters
            if state not in cls._auth_states:
                print("⚠️  Invalid or expired state parameter")
                return None

            auth_data = cls._auth_states.pop(state)
            code_verifier = auth_data["code_verifier"]
            redirect_uri = auth_data["redirect_uri"]

            # Fetch the discovery document to get the correct token endpoint
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(discovery_url, timeout=10.0)
                    response.raise_for_status()
                    discovery_doc = response.json()

                    token_url = discovery_doc.get("token_endpoint")
                    if not token_url:
                        raise ValueError(
                            "token_endpoint not found in discovery document"
                        )

                    print(f"🔍 Fetched token endpoint from discovery: {token_url}")

            except Exception as e:
                print(f"⚠️  Failed to fetch discovery document: {e}")
                # Fallback to environment variable
                cognito_domain = os.getenv("COGNITO_DOMAIN")
                if cognito_domain:
                    token_url = f"https://{cognito_domain}/oauth2/token"
                    print(f"   Using COGNITO_DOMAIN from environment: {cognito_domain}")
                else:
                    raise ValueError(
                        f"Failed to fetch discovery document and COGNITO_DOMAIN not set: {e}"
                    )

            # Prepare token request using the correct endpoint

            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            # Add client authentication if secret is provided
            if client_secret:
                auth_string = f"{client_id}:{client_secret}"
                auth_b64 = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
                headers["Authorization"] = f"Basic {auth_b64}"
                print("🔐 Using client secret for token exchange")

            # Prepare request body
            body = {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }

            # Exchange code for tokens
            print("🔄 Exchanging authorization code for tokens...")

            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, headers=headers, data=body)

                if response.status_code != 200:
                    print(f"❌ Token exchange failed: {response.status_code}")
                    print(f"   Response: {response.text}")
                    return None

                tokens = response.json()

                print("✅ Successfully obtained tokens from Hosted UI")
                if "id_token" in tokens:
                    print(f"   ID token: {tokens['id_token'][:50]}...")
                if "access_token" in tokens:
                    print(f"   Access token: {tokens['access_token'][:50]}...")
                if "refresh_token" in tokens:
                    print(f"   Refresh token: {tokens['refresh_token'][:50]}...")
                else:
                    print("   ⚠️ No refresh token returned")

                return tokens

        except Exception as e:
            print(f"❌ Error exchanging code for token: {e}")
            return None

    @classmethod
    def get_token_from_hosted_ui(
        cls, discovery_url: str, client_id: str, redirect_uri: str
    ) -> str:
        """
        Initiate Hosted UI flow and return authorization URL.

        This is a helper method that returns the URL the user should visit.
        The actual token exchange happens in the callback handler.

        Args:
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            redirect_uri: Where to redirect after login

        Returns:
            Authorization URL for user to visit
        """
        auth_url, _state = cls.get_authorization_url(
            discovery_url=discovery_url, client_id=client_id, redirect_uri=redirect_uri
        )

        return auth_url

    @classmethod
    async def refresh_tokens(
        cls,
        discovery_url: str,
        client_id: str,
        refresh_token: str,
        client_secret: Optional[str] = None,
        scope: str = "openid email profile offline_access",
    ) -> Optional[Dict[str, Any]]:
        """
        Refresh OAuth tokens using a refresh token.

        Args:
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            refresh_token: Refresh token from previous authentication
            client_secret: Optional client secret for confidential clients
            scope: OAuth scopes to request (including openid to get new ID token)

        Returns:
            New token response dict or None if refresh fails
        """
        try:
            # Fetch the discovery document to get the token endpoint
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url, timeout=10.0)
                response.raise_for_status()
                discovery_doc = response.json()

                token_url = discovery_doc.get("token_endpoint")
                if not token_url:
                    raise ValueError("token_endpoint not found in discovery document")

            # Prepare token refresh request
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            # Add client authentication if secret is provided
            if client_secret:
                auth_string = f"{client_id}:{client_secret}"
                auth_b64 = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
                headers["Authorization"] = f"Basic {auth_b64}"

            # Prepare request body with scope to request new ID token
            body = {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
                "scope": scope,  # Include scope to potentially get new ID token
            }

            print("🔄 Refreshing OAuth tokens with scope: " + scope)

            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, headers=headers, data=body)

                if response.status_code != 200:
                    print(f"❌ Token refresh failed: {response.status_code}")
                    print(f"   Response: {response.text}")
                    return None

                tokens = response.json()

                print("✅ Successfully refreshed tokens")
                if "id_token" in tokens:
                    print(f"   New ID token: {tokens['id_token'][:50]}... ✨ (NEW!)")
                else:
                    print(f"   ⚠️  No new ID token returned (IDP may not support this)")
                if "access_token" in tokens:
                    print(f"   New access token: {tokens['access_token'][:50]}...")
                if "refresh_token" in tokens:
                    print(f"   New refresh token: {tokens['refresh_token'][:50]}...")

                return tokens

        except Exception as e:
            print(f"❌ Error refreshing tokens: {e}")
            return None

    @classmethod
    def store_tokens(
        cls,
        session_id: str,
        tokens: Dict[str, Any],
        discovery_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Optional[TokenData]:
        """
        Store tokens with expiry information for proactive refresh.

        Args:
            session_id: Unique session identifier
            tokens: Token response from OAuth
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            client_secret: Optional client secret

        Returns:
            TokenData object or None if parsing fails
        """
        try:
            # Get existing token data if this is a refresh
            existing_token_data = cls._token_store.get(session_id)
            
            # Extract tokens from response, preserving existing ones if not returned
            id_token = tokens.get("id_token") or (existing_token_data.id_token if existing_token_data else "")
            access_token = tokens.get("access_token") or (existing_token_data.access_token if existing_token_data else "")
            refresh_token = tokens.get("refresh_token") or (existing_token_data.refresh_token if existing_token_data else None)

            # Parse expiry from tokens, preserving existing expiry if token unchanged
            id_token_expires_at = existing_token_data.id_token_expires_at if existing_token_data else 0.0
            access_token_expires_at = existing_token_data.access_token_expires_at if existing_token_data else 0.0

            # Update ID token expiry if we have a new ID token
            if tokens.get("id_token"):
                id_payload = decode_jwt_without_validation(id_token)
                if id_payload and "exp" in id_payload:
                    id_token_expires_at = float(id_payload["exp"])
                    print(
                        f"📅 ID token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(id_token_expires_at))}"
                    )
            elif existing_token_data:
                print(f"♻️  Preserving existing ID token (expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(id_token_expires_at))})")

            # Update access token expiry if we have a new access token
            if tokens.get("access_token"):
                access_payload = decode_jwt_without_validation(access_token)
                if access_payload and "exp" in access_payload:
                    access_token_expires_at = float(access_payload["exp"])
                    print(
                        f"📅 Access token expires at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_token_expires_at))}"
                    )

            # Create TokenData
            token_data = TokenData(
                id_token=id_token,
                access_token=access_token,
                refresh_token=refresh_token,
                id_token_expires_at=id_token_expires_at,
                access_token_expires_at=access_token_expires_at,
                discovery_url=discovery_url,
                client_id=client_id,
                client_secret=client_secret,
                session_id=session_id,
            )

            # Store in token store (in-memory)
            cls._token_store[session_id] = token_data

            # Persist to disk for survival across restarts
            import asyncio
            from chainlit.oauth_token_store import TokenPersistence
            
            # Convert TokenData to dict for serialization
            token_dict = {
                "id_token": token_data.id_token,
                "access_token": token_data.access_token,
                "refresh_token": token_data.refresh_token,
                "id_token_expires_at": token_data.id_token_expires_at,
                "access_token_expires_at": token_data.access_token_expires_at,
                "discovery_url": token_data.discovery_url,
                "client_id": token_data.client_id,
                "client_secret": token_data.client_secret,
                "session_id": token_data.session_id,
            }
            
            # Save asynchronously
            asyncio.create_task(TokenPersistence.save_tokens(session_id, token_dict))

            # Log refresh status
            time_until_expiry = token_data.time_until_id_token_expiry()
            print(
                f"💾 Stored tokens for session: {session_id} (ID token expires in {time_until_expiry / 60:.1f} minutes)"
            )

            return token_data

        except Exception as e:
            print(f"❌ Error storing tokens: {e}")
            return None

    @classmethod
    def get_stored_tokens(cls, session_id: str) -> Optional[TokenData]:
        """
        Retrieve stored tokens for a session.

        Args:
            session_id: Unique session identifier

        Returns:
            TokenData object or None if not found
        """
        return cls._token_store.get(session_id)

    @classmethod
    def remove_stored_tokens(cls, session_id: str) -> None:
        """
        Remove stored tokens for a session (both memory and disk).

        Args:
            session_id: Unique session identifier
        """
        if session_id in cls._token_store:
            del cls._token_store[session_id]
            print(f"🗑️  Removed tokens from memory for session: {session_id}")

        # Also delete from disk
        import asyncio
        from chainlit.oauth_token_store import TokenPersistence

        asyncio.create_task(TokenPersistence.delete_tokens(session_id))

    @classmethod
    def get_all_sessions(cls) -> Dict[str, TokenData]:
        """
        Get all stored token sessions.

        Returns:
            Dictionary of session_id to TokenData
        """
        return cls._token_store.copy()

    @classmethod
    def get_token_for_mcp(
        cls, discovery_url: str, client_id: str, token_type: str = "access_token"
    ) -> Optional[tuple[str, float]]:
        """
        Get OAuth token from store matching MCP OAuth configuration.

        Args:
            discovery_url: OIDC discovery URL
            client_id: OAuth client ID
            token_type: Type of token to return ('access_token' or 'id_token')

        Returns:
            Tuple of (token, time_until_expiry_seconds) or None if not found
        """
        for session_id, token_data in cls._token_store.items():
            if (
                token_data.discovery_url == discovery_url
                and token_data.client_id == client_id
            ):
                if token_type == "id_token":
                    return (
                        token_data.id_token,
                        token_data.time_until_id_token_expiry(),
                    )
                else:
                    return (
                        token_data.access_token,
                        token_data.time_until_access_token_expiry(),
                    )
        return None

    @classmethod
    async def restore_tokens_from_storage(cls) -> int:
        """
        Restore persisted OAuth tokens from disk on startup.

        Returns:
            Number of token sessions restored
        """
        try:
            from chainlit.oauth_token_store import TokenPersistence

            # Load all persisted tokens
            persisted_tokens = await TokenPersistence.load_all_tokens()

            # Convert dict data back to TokenData objects
            restored_count = 0
            for session_id, token_dict in persisted_tokens.items():
                try:
                    token_data = TokenData(
                        id_token=token_dict.get("id_token", ""),
                        access_token=token_dict.get("access_token", ""),
                        refresh_token=token_dict.get("refresh_token"),
                        id_token_expires_at=token_dict.get("id_token_expires_at", 0.0),
                        access_token_expires_at=token_dict.get(
                            "access_token_expires_at", 0.0
                        ),
                        discovery_url=token_dict.get("discovery_url", ""),
                        client_id=token_dict.get("client_id", ""),
                        client_secret=token_dict.get("client_secret"),
                        session_id=token_dict.get("session_id", session_id),
                    )

                    # Store in memory
                    cls._token_store[session_id] = token_data
                    restored_count += 1

                    # Log token status
                    time_until_expiry = token_data.time_until_id_token_expiry()
                    print(
                        f"   ↪️  Session {session_id[:8]}... (expires in {time_until_expiry / 60:.1f} min)"
                    )

                except Exception as e:
                    print(
                        f"⚠️  Failed to restore session {session_id[:8]}...: {e}"
                    )
                    continue

            if restored_count > 0:
                print(f"✅ Restored {restored_count} OAuth token session(s) from storage")
            else:
                print("📭 No persisted OAuth tokens found")

            return restored_count

        except Exception as e:
            print(f"❌ Failed to restore tokens from storage: {e}")
            return 0
