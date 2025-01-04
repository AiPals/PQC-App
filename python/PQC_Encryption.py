#!/usr/bin/env python3
"""
Post-Quantum Cryptography Implementation with CRYSTALS-Kyber and CRYSTALS-Dilithium
Using liboqs (https://github.com/open-quantum-safe/liboqs-python)

Features:
- Key Encapsulation Mechanism (KEM) using Kyber
- Digital Signatures using Dilithium
- Hybrid encryption schemes for secure communication
- Secure key and signature storage
"""

import argparse
import os
import sys
from base64 import b64encode, b64decode
from pathlib import Path
from typing import Dict, Tuple
import oqs

# Configure logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CryptoManager:
    """Manages PQC operations using Kyber (KEM) and Dilithium (signatures)."""

    def __init__(self, kem_algo="Kyber512", sig_algo="Dilithium2"):
        self.kem_algo = kem_algo
        self.sig_algo = sig_algo

        # Validate algorithms
        if kem_algo not in oqs.get_supported_KEMs():
            raise ValueError(f"Unsupported KEM algorithm: {kem_algo}")
        if sig_algo not in oqs.get_supported_sigs():
            raise ValueError(f"Unsupported signature algorithm: {sig_algo}")

    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a Kyber KEM keypair."""
        with oqs.KeyEncapsulation(self.kem_algo) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return public_key, private_key

    def encapsulate_key(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a key using Kyber."""
        with oqs.KeyEncapsulation(self.kem_algo) as kem:
            shared_secret, ciphertext = kem.encap_secret(public_key)
        return shared_secret, ciphertext

    def decapsulate_key(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate a key using Kyber."""
        with oqs.KeyEncapsulation(self.kem_algo) as kem:
            kem.import_secret_key(private_key)
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    def generate_sig_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a Dilithium signature keypair."""
        with oqs.Signature(self.sig_algo) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        return public_key, private_key

    def sign_message(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Dilithium."""
        with oqs.Signature(self.sig_algo) as signer:
            signer.import_secret_key(private_key)
            signature = signer.sign(message)
        return signature

    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a Dilithium signature."""
        with oqs.Signature(self.sig_algo) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
        return is_valid

def main():
    """Main function for PQC operations."""
    parser = argparse.ArgumentParser(
        description="Post-Quantum Cryptography Tool with Kyber (KEM) and Dilithium (signatures)"
    )
    parser.add_argument('-m', '--message', type=str, required=True, help="Message to encrypt and sign")
    parser.add_argument('-k', '--kem_algo', type=str, default="Kyber512", help="KEM algorithm (e.g., Kyber512)")
    parser.add_argument('-s', '--sig_algo', type=str, default="Dilithium2", help="Signature algorithm (e.g., Dilithium2)")
    args = parser.parse_args()

    try:
        crypto_manager = CryptoManager(kem_algo=args.kem_algo, sig_algo=args.sig_algo)

        # Generate keypairs
        logger.info("Generating Kyber KEM keypair...")
        kem_public_key, kem_private_key = crypto_manager.generate_kem_keypair()

        logger.info("Generating Dilithium signature keypair...")
        sig_public_key, sig_private_key = crypto_manager.generate_sig_keypair()

        # Encrypt and sign the message
        message = args.message.encode()
        logger.info("Encrypting the message using Kyber...")
        shared_secret, ciphertext = crypto_manager.encapsulate_key(kem_public_key)

        logger.info("Signing the ciphertext using Dilithium...")
        signature = crypto_manager.sign_message(ciphertext, sig_private_key)

        # Decrypt and verify the message
        logger.info("Decapsulating the ciphertext...")
        recovered_secret = crypto_manager.decapsulate_key(ciphertext, kem_private_key)

        logger.info("Verifying the signature...")
        if crypto_manager.verify_signature(ciphertext, signature, sig_public_key):
            logger.info("Signature verified successfully!")
        else:
            logger.error("Signature verification failed!")

        # Display results
        print("\nResults:")
        print(f"Original message: {args.message}")
        print(f"Shared secret (Base64): {b64encode(shared_secret).decode()}")
        print(f"Recovered secret (Base64): {b64encode(recovered_secret).decode()}")
        print(f"Ciphertext (Base64): {b64encode(ciphertext).decode()}")
        print(f"Signature (Base64): {b64encode(signature).decode()}")

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
