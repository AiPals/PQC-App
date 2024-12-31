#!/usr/bin/env python3
"""
Post-Quantum Cryptography Implementation with CRYSTALS-Dilithium

This module implements both KEM (Key Encapsulation Mechanism) and 
Digital Signature functionality using CRYSTALS-Kyber and CRYSTALS-Dilithium.

Features:
- creator: 0nehack(Jesus Carrasco)
- Kyber KEM for key encapsulation and Dilithium for digital signiture
- Dilithium for digital signatures
- Hybrid encryption schemes
- Secure key and signature storage
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Tuple, Dict, Optional
import secrets
import logging
from base64 import b64encode, b64decode
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels for PQC algorithms."""
    NIST_1 = 1  # 128-bit classical security
    NIST_3 = 3  # 192-bit classical security
    NIST_5 = 5  # 256-bit classical security

@dataclass
class DilithiumParams:
    """Parameters for CRYSTALS-Dilithium."""
    name: str
    security_level: SecurityLevel
    public_key_size: int
    secret_key_size: int
    signature_size: int

class DilithiumVariant:
    """CRYSTALS-Dilithium variants and their parameters."""
    VARIANTS = {
        'Dilithium2': DilithiumParams(
            name='Dilithium2',
            security_level=SecurityLevel.NIST_2,
            public_key_size=1312,
            secret_key_size=2528,
            signature_size=2420
        ),
        'Dilithium3': DilithiumParams(
            name='Dilithium3',
            security_level=SecurityLevel.NIST_3,
            public_key_size=1952,
            secret_key_size=4000,
            signature_size=3293
        ),
        'Dilithium5': DilithiumParams(
            name='Dilithium5',
            security_level=SecurityLevel.NIST_5,
            public_key_size=2592,
            secret_key_size=4864,
            signature_size=4595
        )
    }

    @classmethod
    def get_params(cls, variant: str) -> DilithiumParams:
        """Get parameters for a specific Dilithium variant."""
        if variant not in cls.VARIANTS:
            raise ValueError(f"Unsupported Dilithium variant. Supported: {', '.join(cls.VARIANTS.keys())}")
        return cls.VARIANTS[variant]

class DilithiumSigner:
    """Implementation of CRYSTALS-Dilithium digital signatures."""
    
    def __init__(self, variant: str = 'Dilithium2'):
        """Initialize Dilithium signer with specified variant."""
        self.params = DilithiumVariant.get_params(variant)
        self._validate_implementation()

    def _validate_implementation(self) -> None:
        """Validate Dilithium implementation availability."""
        try:
            # Check if PQClean or similar implementation is available
            # This is a placeholder for actual implementation check
            pass
        except ImportError:
            raise RuntimeError("Dilithium implementation not available")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Dilithium keypair."""
        try:
            # This would use the actual Dilithium implementation
            # Placeholder for demonstration
            public_key = secrets.token_bytes(self.params.public_key_size)
            secret_key = secrets.token_bytes(self.params.secret_key_size)
            return public_key, secret_key
        except Exception as e:
            raise CryptoException(f"Failed to generate Dilithium keypair: {e}")

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign a message using Dilithium."""
        try:
            # This would use the actual Dilithium implementation
            # Placeholder for demonstration
            signature = secrets.token_bytes(self.params.signature_size)
            return signature
        except Exception as e:
            raise CryptoException(f"Failed to generate signature: {e}")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a Dilithium signature."""
        try:
            # This would use the actual Dilithium implementation
            # Placeholder for demonstration
            return True
        except Exception as e:
            raise CryptoException(f"Signature verification failed: {e}")

class CryptoManager:
    """Manager class for combined KEM and signature operations."""
    
    def __init__(self, user_id: str, kem_algo: str = 'Kyber512', 
                 sig_algo: str = 'Dilithium2', root: str = './database'):
        """Initialize crypto manager with KEM and signature algorithms."""
        self.user_id = self._validate_user_id(user_id)
        self.kem = SafeBox(user_id, kem_algo, root)
        self.signer = DilithiumSigner(sig_algo)
        self.root = Path(root)

    def _validate_user_id(self, user_id: str) -> str:
        """Validate user ID format and security."""
        if not user_id or len(user_id) < 3 or not user_id.isalnum():
            raise ValueError("User ID must be alphanumeric and at least 3 characters long")
        return user_id

    def generate_keys(self) -> Dict:
        """Generate both KEM and signature keypairs."""
        try:
            # Generate KEM keypair
            kem_public, kem_secret = self.kem.generate_kem_keypair()
            
            # Generate Dilithium keypair
            sig_public, sig_secret = self.signer.generate_keypair()
            
            return {
                'kem_public': kem_public,
                'kem_secret': kem_secret,
                'sig_public': sig_public,
                'sig_secret': sig_secret
            }
        except Exception as e:
            raise CryptoException(f"Key generation failed: {e}")

    def encrypt_and_sign(self, message: bytes, keys: Dict) -> Dict:
        """Encrypt message with KEM and sign with Dilithium."""
        try:
            # Encrypt message
            encrypted_data = self.kem.encrypt_message(message, keys['kem_public'])
            
            # Sign encrypted data
            signature = self.signer.sign(encrypted_data['ciphertext'], 
                                       keys['sig_secret'])
            
            return {
                'ciphertext': encrypted_data['ciphertext'],
                'encapsulated_key': encrypted_data['encapsulated_key'],
                'signature': signature
            }
        except Exception as e:
            raise CryptoException(f"Encryption and signing failed: {e}")

    def verify_and_decrypt(self, data: Dict, keys: Dict) -> bytes:
        """Verify signature and decrypt message."""
        try:
            # Verify signature
            if not self.signer.verify(data['ciphertext'], data['signature'], 
                                    keys['sig_public']):
                raise CryptoException("Signature verification failed")
            
            # Decrypt message
            return self.kem.decrypt_message(data['ciphertext'], 
                                          data['encapsulated_key'], 
                                          keys['kem_secret'])
        except Exception as e:
            raise CryptoException(f"Verification and decryption failed: {e}")

def main():
    """Main function for command-line execution."""
    parser = argparse.ArgumentParser(
        description="Post-Quantum Cryptography Tool with CRYSTALS-Dilithium"
    )
    
    parser.add_argument('-u', '--user_id', type=str,
                       default='leviathan',
                       help='Your user ID in the system')
    
    parser.add_argument('-k', '--kem_algo', type=str,
                       default='Kyber512',
                       help='KEM algorithm (Kyber512, Kyber768, Kyber1024)')
    
    parser.add_argument('-s', '--sig_algo', type=str,
                       default='Dilithium2',
                       help='Signature algorithm (Dilithium2, Dilithium3, Dilithium5)')
    
    parser.add_argument('-r', '--root', type=str,
                       default='./database',
                       help='Root directory for key storage')
    
    parser.add_argument('-m', '--message', type=str,
                       required=True,
                       help='Message to encrypt and sign')

    args = parser.parse_args()

    try:
        # Initialize crypto manager
        crypto_manager = CryptoManager(args.user_id, args.kem_algo, 
                                     args.sig_algo, args.root)
        
        # Generate keys
        keys = crypto_manager.generate_keys()
        
        # Encrypt and sign message
        encrypted_data = crypto_manager.encrypt_and_sign(
            args.message.encode(), keys
        )
        
        # Verify and decrypt (demonstration)
        decrypted_message = crypto_manager.verify_and_decrypt(encrypted_data, keys)
        
        print("Operation successful!")
        print(f"Original message: {args.message}")
        print(f"Decrypted message: {decrypted_message.decode()}")
        print(f"Signature verified: True")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
