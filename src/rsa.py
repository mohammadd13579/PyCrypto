# This file implements the RSA public-key cryptosystem from scratch.

import src.math_utils as math_utils
import math

class RsaKeyPair:
    """A simple container for a public/private key pair."""
    def __init__(self, e, d, n):
        self.e = e  # Public exponent
        self.d = d  # Private exponent
        self.n = n  # Modulus
        self.public_key = (e, n)
        self.private_key = (d, n)

def generate_keypair(bits: int = 1024) -> RsaKeyPair:
    """
    Generates an RSA key pair.
    
    1. Find two large primes, p and q.
    2. Calculate n = p * q (modulus).
    3. Calculate phi(n) = (p-1) * (q-1) (Euler's totient).
    4. Choose a public exponent e (commonly 65537).
    5. Calculate the private exponent d, the modular inverse of e mod phi(n).
    """
    if bits < 64:
        raise ValueError("Key size must be at least 64 bits")
        
    p = math_utils.generate_prime(bits // 2)
    q = math_utils.generate_prime(bits // 2)
    
    # Ensure p and q are distinct
    while p == q:
        q = math_utils.generate_prime(bits // 2)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Use common public exponent e = 65537
    e = 65537
    
    # Ensure e is coprime to phi_n
    while math_utils.egcd(e, phi_n)[0] != 1:
        e = math_utils.generate_prime(17) # Find a new small prime e

    # Calculate private exponent d
    d = math_utils.mod_inverse(e, phi_n)
    
    return RsaKeyPair(e, d, n)

def _bytes_to_int(data: bytes) -> int:
    """Converts a byte string to an integer (big-endian)."""
    return int.from_bytes(data, 'big')

def _int_to_bytes(integer: int, n_bytes: int) -> bytes:
    """Converts an integer to a byte string (big-endian) of length n_bytes."""
    return integer.to_bytes(n_bytes, 'big')

def encrypt(public_key: tuple[int, int], message: bytes) -> bytes:
    """
    Encrypts a byte message using the public key (e, n).
    
    This is a "textbook" encryption.
    Ciphertext = (MessageInt ^ e) % n
    """
    e, n = public_key
    
    # Calculate byte size of modulus
    n_bytes = math.ceil(n.bit_length() / 8)
    
    # Convert message to integer
    m_int = _bytes_to_int(message)
    
    if m_int >= n:
        raise ValueError(f"Message size ({len(message)} bytes) is too large for this key.")

    # Perform modular exponentiation
    c_int = math_utils.pow_mod(m_int, e, n)
    
    # Convert back to bytes, padded to the size of the modulus
    return _int_to_bytes(c_int, n_bytes)

def decrypt(private_key: tuple[int, int], ciphertext: bytes) -> bytes:
    """
    Decrypts a byte message using the private key (d, n).
    
    Message = (CiphertextInt ^ d) % n
    """
    d, n = private_key
    
    # Calculate byte size of modulus
    n_bytes = math.ceil(n.bit_length() / 8)

    # Convert ciphertext to integer
    c_int = _bytes_to_int(ciphertext)
    
    # Perform modular exponentiation
    m_int = math_utils.pow_mod(c_int, d, n)
    
    # Convert back to bytes. The padding here is tricky.
    # We must strip leading null bytes that were added during encryption.
    # We assume the original message was shorter than the modulus.
    try:
        # Try to fit into n_bytes, but it might be smaller
        return m_int.to_bytes(n_bytes, 'big').lstrip(b'\x00')
    except OverflowError:
        # Fallback if m_int is larger than n_bytes can hold
        # (shouldn't happen in standard decryption)
        return m_int.to_bytes(n_bytes + 1, 'big').lstrip(b'\x00')
