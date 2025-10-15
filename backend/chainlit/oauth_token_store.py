"""
OAuth Token Persistence Layer
Encrypts and stores OAuth tokens to disk for persistence across application restarts.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet

from chainlit.config import config
from chainlit.logger import logger


class TokenPersistence:
    """Handles encrypted storage and retrieval of OAuth tokens."""

    _cipher: Optional[Fernet] = None
    _storage_dir: Optional[Path] = None

    @classmethod
    def _get_or_create_secret_key(cls) -> str:
        """
        Get or create a secret key for token encryption.
        
        Priority:
        1. Use CHAINLIT_AUTH_SECRET if set
        2. Load from .chainlit/oauth_secret.key if exists
        3. Generate new random key and save it
        """
        # Try Chainlit's auth secret first
        secret = config.chainlit_server
        if secret:
            logger.debug("Using CHAINLIT_AUTH_SECRET for token encryption")
            return secret
        
        # Try loading existing secret key file
        secret_key_file = Path(config.root) / ".chainlit" / "oauth_secret.key"
        
        if secret_key_file.exists():
            try:
                secret = secret_key_file.read_text().strip()
                if secret:
                    logger.debug("Loaded encryption key from oauth_secret.key")
                    return secret
            except Exception as e:
                logger.warning(f"Failed to load oauth_secret.key: {e}")
        
        # Generate new random secret key
        import secrets
        
        secret = secrets.token_urlsafe(32)  # 32 bytes = 256 bits
        
        # Save it for future use
        try:
            secret_key_file.parent.mkdir(parents=True, exist_ok=True)
            secret_key_file.write_text(secret)
            os.chmod(secret_key_file, 0o600)  # Only owner can read/write
            logger.info(f"✨ Generated new encryption key and saved to {secret_key_file}")
        except Exception as e:
            logger.error(f"Failed to save encryption key: {e}")
        
        return secret

    @classmethod
    def _get_cipher(cls) -> Fernet:
        """Get or create encryption cipher using secret key."""
        if cls._cipher is None:
            # Get or create secret key
            secret = cls._get_or_create_secret_key()

            # Create 32-byte key from secret using SHA256
            key_bytes = hashlib.sha256(secret.encode()).digest()
            key = base64.urlsafe_b64encode(key_bytes)
            cls._cipher = Fernet(key)

        return cls._cipher

    @classmethod
    def _get_storage_dir(cls) -> Path:
        """Get or create the token storage directory."""
        if cls._storage_dir is None:
            # Store tokens in .chainlit directory
            storage_path = Path(config.root) / ".chainlit" / "oauth_tokens"
            storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            cls._storage_dir = storage_path

        return cls._storage_dir

    @classmethod
    def _get_token_file_path(cls, session_id: str) -> Path:
        """Get the file path for a specific session's tokens."""
        # Use session_id as filename (sanitized)
        safe_session_id = "".join(c if c.isalnum() else "_" for c in session_id)
        return cls._get_storage_dir() / f"{safe_session_id}.enc"

    @classmethod
    async def save_tokens(cls, session_id: str, token_data: dict) -> bool:
        """
        Encrypt and save tokens to disk.

        Args:
            session_id: Unique session identifier
            token_data: Dictionary containing token information

        Returns:
            True if successful, False otherwise
        """
        try:
            cipher = cls._get_cipher()
            file_path = cls._get_token_file_path(session_id)

            # Convert token data to JSON
            json_data = json.dumps(token_data, default=str)

            # Encrypt the data
            encrypted_data = cipher.encrypt(json_data.encode())

            # Write to file with restricted permissions
            file_path.write_bytes(encrypted_data)
            os.chmod(file_path, 0o600)  # Only owner can read/write

            logger.debug(f"💾 Saved encrypted tokens for session {session_id[:8]}...")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to save tokens for session {session_id[:8]}...: {e}")
            return False

    @classmethod
    async def load_tokens(cls, session_id: str) -> Optional[dict]:
        """
        Load and decrypt tokens from disk.

        Args:
            session_id: Unique session identifier

        Returns:
            Dictionary containing token information, or None if not found
        """
        try:
            cipher = cls._get_cipher()
            file_path = cls._get_token_file_path(session_id)

            if not file_path.exists():
                return None

            # Read encrypted data
            encrypted_data = file_path.read_bytes()

            # Decrypt the data
            decrypted_data = cipher.decrypt(encrypted_data)

            # Parse JSON
            token_data = json.loads(decrypted_data.decode())

            logger.debug(f"📂 Loaded encrypted tokens for session {session_id[:8]}...")
            return token_data

        except Exception as e:
            logger.warning(
                f"⚠️  Failed to load tokens for session {session_id[:8]}...: {e}"
            )
            # If decryption fails, delete corrupted file
            try:
                file_path = cls._get_token_file_path(session_id)
                if file_path.exists():
                    file_path.unlink()
            except Exception:
                pass
            return None

    @classmethod
    async def delete_tokens(cls, session_id: str) -> bool:
        """
        Remove tokens from disk.

        Args:
            session_id: Unique session identifier

        Returns:
            True if successful, False otherwise
        """
        try:
            file_path = cls._get_token_file_path(session_id)

            if file_path.exists():
                file_path.unlink()
                logger.debug(f"🗑️  Deleted tokens for session {session_id[:8]}...")
                return True

            return False

        except Exception as e:
            logger.error(
                f"❌ Failed to delete tokens for session {session_id[:8]}...: {e}"
            )
            return False

    @classmethod
    async def load_all_tokens(cls) -> Dict[str, dict]:
        """
        Load all persisted tokens on startup.

        Returns:
            Dictionary mapping session_id to token data
        """
        tokens = {}

        try:
            storage_dir = cls._get_storage_dir()

            if not storage_dir.exists():
                return tokens

            # Iterate through all encrypted token files
            for token_file in storage_dir.glob("*.enc"):
                # Extract session_id from filename
                session_id = token_file.stem  # Remove .enc extension

                # Load tokens for this session
                token_data = await cls.load_tokens(session_id)

                if token_data:
                    tokens[session_id] = token_data

            if tokens:
                logger.info(f"✅ Restored {len(tokens)} token session(s) from storage")
            else:
                logger.debug("📭 No persisted tokens found")

        except Exception as e:
            logger.error(f"❌ Failed to load tokens from storage: {e}")

        return tokens

    @classmethod
    async def cleanup_expired_tokens(cls, valid_session_ids: set) -> int:
        """
        Remove token files for sessions that no longer exist.

        Args:
            valid_session_ids: Set of currently active session IDs

        Returns:
            Number of token files deleted
        """
        deleted_count = 0

        try:
            storage_dir = cls._get_storage_dir()

            if not storage_dir.exists():
                return 0

            # Iterate through all token files
            for token_file in storage_dir.glob("*.enc"):
                session_id = token_file.stem

                # Delete if session is no longer valid
                if session_id not in valid_session_ids:
                    try:
                        token_file.unlink()
                        deleted_count += 1
                        logger.debug(
                            f"🗑️  Cleaned up tokens for expired session {session_id[:8]}..."
                        )
                    except Exception as e:
                        logger.warning(
                            f"⚠️  Failed to delete expired token file {token_file}: {e}"
                        )

            if deleted_count > 0:
                logger.info(f"🧹 Cleaned up {deleted_count} expired token file(s)")

        except Exception as e:
            logger.error(f"❌ Failed to cleanup expired tokens: {e}")

        return deleted_count

