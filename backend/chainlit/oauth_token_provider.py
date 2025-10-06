"""
OAuth token provider for automatic token generation.
This module handles automatic token acquisition for MCP server authentication using AWS Cognito.
"""
import boto3
import os
import hmac
import hashlib
import base64
from typing import Optional, Dict, Any


class TokenProvider:
    """Provides OAuth tokens automatically from AWS Cognito"""
    
    @staticmethod
    def _calculate_secret_hash(username: str, client_id: str, client_secret: str) -> str:
        """
        Calculate SECRET_HASH for Cognito authentication.
        Required when app client has a secret configured.
        """
        message = username + client_id
        dig = hmac.new(
            client_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()
    
    @staticmethod
    def get_cognito_token(
        user_pool_id: str,
        client_id: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        region: str = "us-east-1"
    ) -> Optional[str]:
        """
        Get a fresh ID token from AWS Cognito.
        
        Args:
            user_pool_id: Cognito User Pool ID
            client_id: App Client ID
            username: Username (can be from env if not provided)
            password: Password (can be from env if not provided)
            region: AWS region
            
        Returns:
            ID token string or None
        """
        try:
            # Get credentials from environment if not provided
            if not username:
                username = os.getenv("COGNITO_USERNAME")
            if not password:
                password = os.getenv("COGNITO_PASSWORD")
            
            if not username or not password:
                print("⚠️  Cognito credentials not found in environment")
                return None
            
            # Get optional client secret (required if app client has secret)
            client_secret = os.getenv("COGNITO_CLIENT_SECRET")
            
            # Initialize Cognito client
            client = boto3.client('cognito-idp', region_name=region)
            
            # Prepare auth parameters
            auth_params = {
                'USERNAME': username,
                'PASSWORD': password
            }
            
            # Add SECRET_HASH if client secret is provided
            if client_secret:
                secret_hash = TokenProvider._calculate_secret_hash(username, client_id, client_secret)
                auth_params['SECRET_HASH'] = secret_hash
                print(f"🔐 Using client secret for authentication")
            
            # Initiate auth
            response = client.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters=auth_params
            )
            
            # Extract ID token
            if 'AuthenticationResult' in response:
                id_token = response['AuthenticationResult']['IdToken']
                print(f"✅ Fresh ID token obtained from Cognito")
                return id_token
            else:
                print("⚠️  No authentication result in Cognito response")
                return None
                
        except Exception as e:
            print(f"❌ Error getting token from Cognito: {e}")
            return None
    
    @classmethod
    def get_token(cls, 
                  discovery_url: str,
                  client_id: str) -> Optional[str]:
        """
        Get a token automatically using Cognito credentials.
        
        Args:
            discovery_url: OIDC discovery URL (to extract user pool ID and region)
            client_id: OAuth client ID
            
        Returns:
            Token string or None
        """
        try:
            # Parse user pool ID and region from discovery URL
            # Format: https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/openid-configuration
            parts = discovery_url.split('/')
            if len(parts) >= 4 and 'cognito-idp' in discovery_url:
                # Extract region from hostname
                hostname = parts[2]  # cognito-idp.{region}.amazonaws.com
                region = hostname.split('.')[1]
                
                # Extract user pool ID
                user_pool_id = parts[3]
                
                print(f"🔄 Attempting to obtain fresh token from Cognito...")
                print(f"   Region: {region}")
                print(f"   User Pool: {user_pool_id}")
                print(f"   Client ID: {client_id}")
                
                return cls.get_cognito_token(
                    user_pool_id=user_pool_id,
                    client_id=client_id,
                    region=region
                )
            else:
                print(f"⚠️  Could not parse Cognito info from discovery URL")
                return None
                
        except Exception as e:
            print(f"❌ Error obtaining token: {e}")
            return None

