import os
import hashlib
import base64
import re
import json
from ecdsa import SigningKey, NIST521p
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from datetime import datetime

# Aadhaar number validation function
def validate_aadhaar(aadhaar_number):
    if not re.fullmatch(r'\d{12}', aadhaar_number):
        raise ValueError("Invalid Aadhaar number. It should be exactly 12 digits.")
    return aadhaar_number

# Generate a random salt
def generate_salt():
    return os.urandom(16)  # 128-bit random salt

# Generate a unique nonce
def generate_nonce():
    return os.urandom(16)  # 128-bit random nonce

# Hash the Aadhaar number with salt and nonce using SHA-3
def hash_aadhaar_with_salt_nonce(aadhaar_number, salt, nonce):
    combined = aadhaar_number.encode() + salt + nonce + str(datetime.now()).encode()
    return hashlib.sha3_512(combined).digest()

# Generate a secure ECDSA key pair
def generate_ecdsa_keys():
    private_key = SigningKey.generate(curve=NIST521p)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

# Sign the hashed Aadhaar number using the private key
def sign_data(private_key, hashed_aadhaar):
    signature = private_key.sign(hashed_aadhaar)
    return base64.b64encode(signature).decode('utf-8')

# Encrypt the signature using AES-256
def encrypt_signature(signature):
    key = get_random_bytes(32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_signature = cipher.encrypt(pad(signature.encode(), AES.block_size))
    
    return (
        base64.b64encode(encrypted_signature).decode('utf-8'),
        base64.b64encode(iv).decode('utf-8'),
        key
    )

# Decrypt the signature using AES-256
def decrypt_signature(encrypted_signature, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv))
    decrypted_signature = unpad(cipher.decrypt(base64.b64decode(encrypted_signature)), AES.block_size)
    return decrypted_signature.decode('utf-8')

# Verify the signature using the public key
def verify_signature(public_key, hashed_aadhaar, signature):
    try:
        decoded_signature = base64.b64decode(signature)
        public_key.verify(decoded_signature, hashed_aadhaar)
        print("Signature is valid!")
    except Exception as e:
        print("Signature verification failed:", e)

# Check for duplicate signatures
def check_duplicates(signatures):
    seen_signatures = {}
    for aadhaar, signature in signatures.items():
        if signature in seen_signatures:
            print(f"Duplicate signature found for Aadhaar number: {aadhaar}")
        else:
            seen_signatures[signature] = aadhaar

# Main function to handle input and execute signing and verification process
def main():
    # Load Aadhaar numbers from JSON file
    try:
        with open('aadhaar_numbers.json') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        print("Error: JSON file not found.")
        return
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON.")
        return

    signatures = {}

    for aadhaar in data.get('aadhaars', []):
        try:
            # Validate Aadhaar number
            validated_aadhaar = validate_aadhaar(aadhaar)

            # Generate a random salt and nonce
            salt = generate_salt()
            nonce = generate_nonce()
            print("Generated Salt (Base64):", base64.b64encode(salt).decode('utf-8'))
            print("Generated Nonce (Base64):", base64.b64encode(nonce).decode('utf-8'))

            # Hash the Aadhaar number with the salt and nonce
            hashed_aadhaar = hash_aadhaar_with_salt_nonce(validated_aadhaar, salt, nonce)
            print("Hashed Aadhaar (SHA-3 + Salt + Nonce):", hashed_aadhaar.hex())

            # Generate ECDSA keys
            private_key, public_key = generate_ecdsa_keys()

            # Sign the hashed Aadhaar number
            signature = sign_data(private_key, hashed_aadhaar)
            print("Digital Signature (Base64-encoded):", signature)

            # Encrypt the signature with AES-256
            encrypted_signature, iv, aes_key = encrypt_signature(signature)
            print("Encrypted Signature (AES-256, Base64):", encrypted_signature)
            print("Initialization Vector (Base64):", iv)

            # Store the signature
            signatures[validated_aadhaar] = signature

        except ValueError as ve:
            print("Input Error:", ve)
        except Exception as e:
            print("An error occurred:", e)

    # Check for duplicate signatures
    check_duplicates(signatures)

if __name__ == "__main__":
    main()
