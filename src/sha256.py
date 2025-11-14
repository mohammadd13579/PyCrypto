# This file implements the SHA-256 hash function from scratch.
# It follows the FIPS 180-4 specification.

import struct

# SHA-256 Constants
# ---
# K: Round constants
# These are the first 32 bits of the fractional parts of the
# cube roots of the first 64 prime numbers.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# H: Initial Hash Values
# These are the first 32 bits of the fractional parts of the
# square roots of the first 8 prime numbers.
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Bitwise logical functions
# ---
def _rotr(x: int, n: int, bits: int = 32) -> int:
    """Circular right rotation (rotate right)."""
    mask = (1 << bits) - 1
    return ((x >> n) | (x << (bits - n))) & mask

def _ch(x: int, y: int, z: int) -> int:
    """Choose: (x AND y) XOR (NOT x AND z)"""
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int) -> int:
    """Majority: (x AND y) XOR (x AND z) XOR (y AND z)"""
    return (x & y) ^ (x & z) ^ (y & z)

def _sigma0(x: int) -> int:
    """ROTR 2(x) XOR ROTR 13(x) XOR ROTR 22(x)"""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _sigma1(x: int) -> int:
    """ROTR 6(x) XOR ROTR 11(x) XOR ROTR 25(x)"""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _gamma0(x: int) -> int:
    """ROTR 7(x) XOR ROTR 18(x) XOR SHR 3(x)"""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

def _gamma1(x: int) -> int:
    """ROTR 17(x) XOR ROTR 19(x) XOR SHR 10(x)"""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)

def _add(a: int, b: int, bits: int = 32) -> int:
    """Addition modulo 2^32."""
    return (a + b) & ((1 << bits) - 1)

def _padding(message: bytes) -> bytes:
    """
    Applies the Merkle-Damgård padding to the message.
    1. Append a single '1' bit (0x80 byte).
    2. Append '0' bits until message length % 512 == 448 bits (56 bytes).
    3. Append the original message length as a 64-bit big-endian integer.
    """
    original_len_bits = len(message) * 8
    
    # 1. Append 0x80
    padded = message + b'\x80'
    
    # 2. Append 0x00...
    # Calculate bytes needed to reach 56 bytes (mod 64)
    # (64 bytes per chunk)
    bytes_to_add = (56 - (len(padded) % 64)) % 64
    padded += b'\x00' * bytes_to_add
    
    # 3. Append 64-bit length
    padded += struct.pack('>Q', original_len_bits)
    
    return padded

def _process_chunk(chunk: bytes, h: list[int]) -> list[int]:
    """
    Processes a 512-bit (64-byte) chunk and updates the hash state 'h'.
    """
    if len(chunk) != 64:
        raise ValueError("Chunk must be 64 bytes")
        
    # 1. Prepare the message schedule (w)
    w = [0] * 64
    
    # First 16 words are from the chunk (big-endian 32-bit words)
    for i in range(16):
        w[i] = struct.unpack('>I', chunk[i*4 : i*4 + 4])[0]
        
    # Extend to 64 words
    for i in range(16, 64):
        s0 = _gamma0(w[i-15])
        s1 = _gamma1(w[i-2])
        w[i] = _add(_add(_add(w[i-16], s0), w[i-7]), s1)

    # 2. Initialize working variables
    a, b, c, d, e, f, g, h0 = h

    # 3. Compression loop
    for i in range(64):
        S1 = _sigma1(e)
        ch = _ch(e, f, g)
        temp1 = _add(_add(_add(_add(h0, S1), ch), K[i]), w[i])
        
        S0 = _sigma0(a)
        maj = _maj(a, b, c)
        temp2 = _add(S0, maj)

        h0 = g
        g = f
        f = e
        e = _add(d, temp1)
        d = c
        c = b
        b = a
        a = _add(temp1, temp2)

    # 4. Compute the new intermediate hash value
    return [
        _add(h[0], a),
        _add(h[1], b),
        _add(h[2], c),
        _add(h[3], d),
        _add(h[4], e),
        _add(h[5], f),
        _add(h[6], g),
        _add(h[7], h0)
    ]

def hash(message: str) -> str:
    """
    Computes the SHA-256 hash of a given string.
    Returns the hash as a 64-character hex string.
    """
    # 1. Encode string to bytes (UTF-8)
    message_bytes = message.encode('utf-8')
    
    # 2. Apply padding
    padded_message = _padding(message_bytes)
    
    # 3. Initialize hash state
    h = list(H_INIT)
    
    # 4. Process the message in 64-byte chunks
    for i in range(0, len(padded_message), 64):
        chunk = padded_message[i : i+64]
        h = _process_chunk(chunk, h)
        
    # 5. Concatenate final hash values
    final_hash = ""
    for val in h:
        final_hash += f"{val:08x}"
        
    return final_hash
