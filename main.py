# This file demonstrates the cryptographic algorithms
# implemented in the 'src' directory.

import src.rsa as rsa
import src.aes as aes
import src.sha256 as sha256
import os

def print_banner(title):
    print("\n" + "=" * 60)
    print(f" {title} ".center(60))
    print("=" * 60)

def demo_sha256():
    print_banner("SHA-256 Demonstration")
    
    message1 = "Hello, world!"
    message2 = "This is a test of the PyCryptoFromScratch project."
    message3 = "This is a test of the PyCryptoFromScratch project!" # Note the '!'
    
    hash1 = sha256.hash(message1)
    hash2 = sha256.hash(message2)
    hash3 = sha256.hash(message3)
    
    print(f"Message: '{message1}'")
    print(f"Hash:    {hash1}")
    print(f"Length:  {len(hash1)} characters")
    
    print(f"\nMessage: '{message2}'")
    print(f"Hash:    {hash2}")
    
    print(f"\nMessage: '{message3}'")
    print(f"Hash:    {hash3}")
    
    print("\nNote how a tiny change ('!') in the message completely")
    print("changes the resulting hash (the avalanche effect).")

def demo_rsa():
    print_banner("RSA Demonstration (1024-bit)")
    print("Generating 1024-bit RSA key pair...")
    print("(This may take a moment, as we are finding large primes)")
    
    # Note: 1024 bits is insecure today, but faster for a demo.
    # 2048 or 4096 is standard.
    key_pair = rsa.generate_keypair(bits=1024)
    
    print("Key pair generated.")
    print(f"  Public Modulus (n) (first 10 chars): {str(key_pair.n)[:10]}...")
    print(f"  Public Exponent (e): {key_pair.e}")

    message_str = "This is a secret message for RSA."
    message_bytes = message_str.encode('utf-8')
    
    print(f"\nOriginal Message: '{message_str}'")
    print(f"Original Bytes:   {message_bytes.hex()}")

    try:
        # --- Encryption ---
        print("\nEncrypting with public key...")
        ciphertext = rsa.encrypt(key_pair.public_key, message_bytes)
        print(f"Ciphertext: {ciphertext.hex()}")

        # --- Decryption ---
        print("\nDecrypting with private key...")
        decrypted_bytes = rsa.decrypt(key_pair.private_key, ciphertext)
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        print(f"Decrypted Bytes: {decrypted_bytes.hex()}")
        print(f"Decrypted Message: '{decrypted_str}'")
        
        # --- Verification ---
        if decrypted_str == message_str:
            print("\nVerification: SUCCESS! Original and decrypted messages match.")
        else:
            print("\nVerification: FAILED! Messages do not match.")
            
    except Exception as e:
        print(f"\nAn error occurred during RSA demo: {e}")
        print("This can sometimes happen if the message is too large for the key size.")

def demo_aes():
    print_banner("AES-128 Demonstration (ECB Mode)")
    
    # 16-byte key for AES-128
    key = b'MySecretKey12345' 
    
    # 16-byte block of plaintext
    plaintext_block = b'This is a block!'
    
    print(f"Plaintext: {plaintext_block}")
    print(f"Key:       {key.decode('utf-8')}")
    
    # --- Encryption ---
    print("\nEncrypting block...")
    try:
        encrypted_block = aes.encrypt_block(plaintext_block, key)
        print(f"Ciphertext: {encrypted_block.hex()}")
        
        # --- Decryption ---
        print("\nDecrypting block...")
        decrypted_block = aes.decrypt_block(encrypted_block, key)
        print(f"Decrypted: {decrypted_block}")
        
        # --- Verification ---
        if decrypted_block == plaintext_block:
            print("\nVerification: SUCCESS! Original and decrypted blocks match.")
        else:
            print("\nVerification: FAILED! Blocks do not match.")
            
    except Exception as e:
        print(f"\nAn error occurred during AES demo: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print(" PyCryptoFromScratch Demonstration ".center(60))
    print(" Author: Gemini ".center(60))
    print("=" * 60)
    print("\n⚠️  This is an educational tool. ⚠️")
    print("⚠️  DO NOT USE THIS CODE FOR REAL-WORLD CRYPTOGRAPHY. ⚠️")

    demo_sha256()
    demo_aes()
    demo_rsa()
    print("\n" + "=" * 60)
    print(" Demonstration Complete ".center(60))
    print("=" * 60)
