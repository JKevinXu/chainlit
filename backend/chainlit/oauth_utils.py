"""
OAuth token validation utilities for MCP server authentication.
"""
import time
from typing import Dict, Any, Optional, Tuple

import httpx
import jwt
from jwt import PyJWKClient


# Cache for OIDC configurations and JWKS clients
_oidc_configs: Dict[str, Tuple[Dict[str, Any], float]] = {}
_jwks_clients: Dict[str, Tuple[PyJWKClient, float]] = {}

OIDC_CONFIG_CACHE_TTL = 3600  # 1 hour
JWKS_CACHE_TTL = 3600  # 1 hour


async def get_oidc_config(discovery_url: str) -> Dict[str, Any]:
    """Fetch and cache OIDC discovery configuration."""
    current_time = time.time()
    
    if discovery_url in _oidc_configs:
        config, timestamp = _oidc_configs[discovery_url]
        if current_time - timestamp < OIDC_CONFIG_CACHE_TTL:
            return config
    
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        config = response.json()
        _oidc_configs[discovery_url] = (config, current_time)
        return config


def get_jwks_client(jwks_uri: str) -> PyJWKClient:
    """Get or create a cached JWKS client."""
    current_time = time.time()
    
    if jwks_uri in _jwks_clients:
        client, timestamp = _jwks_clients[jwks_uri]
        if current_time - timestamp < JWKS_CACHE_TTL:
            return client
    
    client = PyJWKClient(jwks_uri)
    _jwks_clients[jwks_uri] = (client, current_time)
    return client


async def validate_oauth_token(
    token: str,
    discovery_url: str,
    allowed_audience: str
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate an OAuth token against the OIDC provider.
    
    Args:
        token: The JWT token to validate
        discovery_url: OIDC discovery endpoint URL
        allowed_audience: Expected audience (client ID) in the token
        
    Returns:
        Tuple of (is_valid, decoded_token_data)
    """
    try:
        # Get OIDC configuration
        oidc_config = await get_oidc_config(discovery_url)
        jwks_uri = oidc_config.get("jwks_uri")
        
        if not jwks_uri:
            print("Error: JWKS URI not found in OIDC discovery configuration.")
            return False, None
        
        # Get JWKS client and signing key
        jwks_client = get_jwks_client(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and validate token
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],  # Cognito typically uses RS256
            audience=allowed_audience,
            options={"verify_exp": True}
        )
        
        return True, data
        
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return False, None
    except jwt.InvalidAudienceError:
        print("Invalid audience.")
        return False, None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return False, None
    except Exception as e:
        print(f"An unexpected error occurred during token validation: {e}")
        return False, None

