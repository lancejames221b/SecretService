"""
Data models for SecretService
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict
from datetime import datetime
import arrow
from eth_typing import HexStr
from eth_keys import keys

class UserCredentials(BaseModel):
    """User credentials and key information"""
    email: EmailStr
    password: str = Field(..., min_length=12)
    service: str = Field(..., regex='^(gmail|microsoft|yahoo)$')
    pub_key_hex: HexStr
    priv_key_hex: HexStr

    @validator('priv_key_hex')
    def validate_private_key(cls, v):
        try:
            keys.PrivateKey(bytes.fromhex(v[2:] if v.startswith('0x') else v))
            return v
        except Exception as e:
            raise ValueError(f'Invalid private key: {e}')

    @validator('pub_key_hex')
    def validate_public_key(cls, v):
        try:
            keys.PublicKey(bytes.fromhex(v[2:] if v.startswith('0x') else v))
            return v
        except Exception as e:
            raise ValueError(f'Invalid public key: {e}')

class EncryptedMessage(BaseModel):
    """Encrypted message format"""
    ciphertext: str
    pub_key_hex: HexStr

class DecryptedMessage(BaseModel):
    """Decrypted message format"""
    plaintext: str

class EmailMessage(BaseModel):
    """Email message format"""
    from_address: EmailStr
    to_address: EmailStr
    subject: str = Field(..., max_length=200)
    message_text: str = Field(..., max_length=10000)
    secret: str
    is_key_request: bool = False

class Contact(BaseModel):
    """Contact information"""
    email: EmailStr
    pub_key: HexStr
    last_key_exchange: datetime

class MessageThread(BaseModel):
    """Message thread information"""
    from_email: EmailStr
    date: datetime
    pub_key: HexStr
    content: str

    @validator('date', pre=True)
    def parse_date(cls, v):
        if isinstance(v, str):
            try:
                return arrow.get(v).datetime
            except Exception as e:
                raise ValueError(f'Invalid date format: {e}')
        return v

class ChaffeMessage(BaseModel):
    """Chaffe (decoy) message format"""
    subject: str
    body: str 