# Aadhaar Signature Verification System

## Overview

The Aadhaar Signature Verification System is a Python-based application designed to securely manage Aadhaar numbers through hashing, digital signing, and encryption. This project leverages cryptographic techniques to ensure the integrity and confidentiality of Aadhaar information, providing a robust solution for verifying identities while maintaining privacy.

## Features

- **Aadhaar Number Validation**: Validates the format of Aadhaar numbers to ensure they consist of exactly 12 digits.
- **Secure Hashing**: Utilizes SHA-3 hashing combined with a salt and nonce to create a unique hash of the Aadhaar number, enhancing security against attacks.
- **Digital Signature Generation**: Generates ECDSA (Elliptic Curve Digital Signature Algorithm) keys to sign the hashed Aadhaar, ensuring authenticity and non-repudiation.
- **Signature Encryption**: Uses AES-256 encryption to securely encrypt the digital signature, ensuring that sensitive information is protected during storage or transmission.
- **Signature Decryption and Verification**: Supports decryption of the encrypted signature and verification against the public key, confirming the validity of the signed data.

## Requirements

To run this project, you need to have the following libraries installed:

- `ecdsa`
- `pycryptodome` (for AES encryption/decryption)
- Python 3.x

You can install the required libraries using pip:

```bash
pip install ecdsa pycryptodome


Code Structure
The project consists of the following key functions:

validate_aadhaar(aadhaar_number): Validates the format of the provided Aadhaar number.
generate_salt(): Generates a random salt for hashing.
generate_nonce(): Generates a unique nonce.
hash_aadhaar_with_salt_nonce(aadhaar_number, salt, nonce): Combines the Aadhaar number, salt, and nonce to produce a SHA-3 hash.
generate_ecdsa_keys(): Generates an ECDSA private and public key pair.
sign_data(private_key, hashed_aadhaar): Signs the hashed Aadhaar number using the private key and encodes it in Base64.
encrypt_signature(signature): Encrypts the digital signature using AES-256.
decrypt_signature(encrypted_signature, iv, key): Decrypts the encrypted signature using AES-256.
verify_signature(public_key, hashed_aadhaar, signature): Verifies the digital signature against the public key.
Security Considerations
Always ensure that private keys are stored securely and not exposed in public repositories.
Handle sensitive data carefully to prevent unauthorized access.
Regularly update the cryptographic libraries to their latest versions to mitigate potential vulnerabilities.


License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Thanks to the contributors of the libraries used in this project.
Special thanks to the cryptographic community for the ongoing development and maintenance of secure algorithms.