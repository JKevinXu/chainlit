"""
OAuth Hosted UI flow for Cognito authentication.
Provides browser-based login flow instead of username/password auth.
"""

import base64
import hashlib
import os
import secrets
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse

import httpx


class HostedUIProvider:
    """Provides OAuth tokens using Cognito Hosted UI flow"""

    # Store state and code verifier for PKCE
    _auth_states: Dict[str, Dict[str, str]] = {}

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
