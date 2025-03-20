"""
Cryptographic utilities for SecretService
"""
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
from eth_keys import keys
from typing import Tuple, Dict
import json
import binascii
from pathlib import Path
from base64 import b64encode, b64decode
from models import UserCredentials, EncryptedMessage, DecryptedMessage
from config import settings
import logging

logger = logging.getLogger(__name__)

class CryptoManager:
    """Handles cryptographic operations for SecretService"""
    
    @staticmethod
    def generate_key_pair() -> Tuple[str, str]:
        """Generate a new ECC key pair
        
        Returns:
            Tuple[str, str]: (private_key_hex, public_key_hex)
        """
        try:
            priv_key = generate_eth_key()
            return priv_key.to_hex(), priv_key.public_key.to_hex()
        except Exception as e:
            logger.error(f"Error generating key pair: {e}")
            raise RuntimeError("Failed to generate key pair")

    @staticmethod
    def encrypt_message(pub_key_hex: str, plaintext: str) -> EncryptedMessage:
        """Encrypt a message using a public key
        
        Args:
            pub_key_hex (str): Public key in hex format
            plaintext (str): Message to encrypt
            
        Returns:
            EncryptedMessage: Encrypted message object
        """
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode()
            encrypted = encrypt(pub_key_hex, plaintext)
            return EncryptedMessage(
                ciphertext=str(binascii.hexlify(encrypted), 'utf-8'),
                pub_key_hex=pub_key_hex
            )
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            raise RuntimeError("Failed to encrypt message")

    @staticmethod
    def decrypt_message(priv_key_hex: str, encrypted_msg: EncryptedMessage) -> DecryptedMessage:
        """Decrypt a message using a private key
        
        Args:
            priv_key_hex (str): Private key in hex format
            encrypted_msg (EncryptedMessage): Encrypted message object
            
        Returns:
            DecryptedMessage: Decrypted message object
        """
        try:
            decrypted = decrypt(priv_key_hex, binascii.unhexlify(encrypted_msg.ciphertext))
            return DecryptedMessage(plaintext=decrypted.decode())
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            raise RuntimeError("Failed to decrypt message")

    @staticmethod
    def encode_secret(secret: str) -> str:
        """Encode a secret for email transport
        
        Args:
            secret (str): Secret to encode
            
        Returns:
            str: Base64 encoded secret
        """
        try:
            return b64encode(bytes.fromhex(bytes(secret, 'utf-8').hex())).decode()
        except Exception as e:
            logger.error(f"Error encoding secret: {e}")
            raise RuntimeError("Failed to encode secret")

    @staticmethod
    def decode_secret(encoded_secret: str) -> str:
        """Decode a secret from email transport
        
        Args:
            encoded_secret (str): Base64 encoded secret
            
        Returns:
            str: Decoded secret
        """
        try:
            return bytes.fromhex(b64decode(encoded_secret + '==').hex()).decode(errors='ignore')
        except Exception as e:
            logger.error(f"Error decoding secret: {e}")
            raise RuntimeError("Failed to decode secret")

class KeyManager:
    """Manages key storage and retrieval"""
    
    def __init__(self):
        self.pubkeys_file = settings.PUBKEYS_FILE
        self.secret_service_file = settings.SECRET_SERVICE_FILE

    def save_user_credentials(self, credentials: UserCredentials) -> None:
        """Save user credentials to file
        
        Args:
            credentials (UserCredentials): User credentials to save
        """
        try:
            data = {
                credentials.email: {
                    'pubKeyHex': credentials.pub_key_hex,
                    'privKeyHex': credentials.priv_key_hex,
                    'password': credentials.password,
                    'service': credentials.service
                }
            }
            with open(self.secret_service_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving user credentials: {e}")
            raise RuntimeError("Failed to save user credentials")

    def load_user_credentials(self) -> Dict[str, UserCredentials]:
        """Load user credentials from file
        
        Returns:
            Dict[str, UserCredentials]: Dictionary of email to credentials
        """
        try:
            if not self.secret_service_file.exists():
                return {}
            with open(self.secret_service_file) as f:
                data = json.load(f)
            return {
                email: UserCredentials(
                    email=email,
                    pub_key_hex=creds['pubKeyHex'],
                    priv_key_hex=creds['privKeyHex'],
                    password=creds['password'],
                    service=creds['service']
                )
                for email, creds in data.items()
            }
        except Exception as e:
            logger.error(f"Error loading user credentials: {e}")
            raise RuntimeError("Failed to load user credentials")

    def save_contact_key(self, email: str, pub_key: str) -> None:
        """Save a contact's public key
        
        Args:
            email (str): Contact's email
            pub_key (str): Contact's public key
        """
        try:
            data = {}
            if self.pubkeys_file.exists():
                with open(self.pubkeys_file) as f:
                    data = json.load(f)
            data[email] = pub_key
            with open(self.pubkeys_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving contact key: {e}")
            raise RuntimeError("Failed to save contact key")

    def get_contact_key(self, email: str) -> str:
        """Get a contact's public key
        
        Args:
            email (str): Contact's email
            
        Returns:
            str: Contact's public key or None if not found
        """
        try:
            if not self.pubkeys_file.exists():
                return None
            with open(self.pubkeys_file) as f:
                data = json.load(f)
            return data.get(email)
        except Exception as e:
            logger.error(f"Error getting contact key: {e}")
            raise RuntimeError("Failed to get contact key") 