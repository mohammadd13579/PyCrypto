PyCryptoFromScratch
===================

A pure-Python implementation of foundational cryptographic algorithms (RSA, AES, SHA-256) built from their mathematical first principles.

⚠️ CRITICAL SECURITY WARNING ⚠️
-------------------------------

**DO NOT USE THIS CODE FOR ANY REAL-WORLD SECURITY APPLICATIONS.**

This library is an educational tool, not a secure cryptographic module. It is built to demonstrate the *mathematics and logic* behind these algorithms, not to provide secure implementations.

Real-world cryptographic libraries (like `cryptography` in Python) are written by security experts and include crucial features not present here, such as:

-   **Constant-Time Operations:** These implementations are likely vulnerable to **timing attacks** and other side-channel attacks.

-   **Secure Padding Schemes:** The RSA implementation uses basic integer conversion, not a secure padding scheme like OAEP or PKCS#1 v1.5, making it vulnerable to attacks.

-   **Secure Mode of Operation:** The AES implementation uses ECB mode for demonstration, which is itself insecure. Secure modes like GCM or CBC are complex to implement correctly.

-   **Rigorous Testing & Vetting:** This code has not undergone the years of public scrutiny and formal verification that secure libraries have.

This project is for **learning and exploration only**.

Project Structure
-----------------

-   `src/math_utils.py`: Core number theory functions (modular exponentiation, primality testing, modular inverse) used by RSA.

-   `src/rsa.py`: The RSA public-key cryptosystem (key generation, encryption, decryption).

-   `src/aes_common.py`: Constants (S-box, Rcon) and the core Galois Field (GF(2^8)) multiplication logic for AES.

-   `src/aes.py`: The AES (Rijndael) block cipher logic.

-   `src/sha256.py`: The SHA-256 hash function.

-   `main.py`: A simple demonstration file to show all the algorithms in action.

How to Run
----------

1.  Ensure you have Python 3.

2.  Run the demonstration:

    ```
    python main.py
    ```

Algorithm Notes
---------------

### RSA

Based on number theory.

-   **Key Generation:** Involves finding two large primes (using Miller-Rabin primality test) and using the Extended Euclidean Algorithm to find the modular inverse for the private key.

-   **Encryption/Decryption:** Based on simple modular exponentiation:

    -   `Ciphertext = (Message ^ e) mod n`

    -   `Message = (Ciphertext ^ d) mod n`

### AES (Advanced Encryption Standard)

Shutterstock

A symmetric block cipher. The "math" here is in a finite field, GF(2^8).

-   **Key Expansion:** Creates a "schedule" of round keys from the initial key.

-   **SubBytes:** A non-linear substitution using a pre-computed lookup table (the S-box). The S-box is mathematically derived from finding the multiplicative inverse in GF(2^8) followed by an affine transformation.

-   **ShiftRows:** A simple permutation of bytes.

-   **MixColumns:** The most complex "math" step. It's a matrix multiplication where each operation is a multiplication or addition in GF(2^8). This is implemented in `aes_common.py`.

-   **AddRoundKey:** A simple XOR of the current state with the round key.

### SHA-256 (Secure Hash Algorithm 256-bit)

A cryptographic hash function based on the Merkle-Damgård construction.

-   **Constants:** The initial hash values (`H`) and round constants (`K`) are mathematically derived from the fractional parts of the square roots and cube roots of the first 8 and 64 prime numbers, respectively.

-   **Padding:** The input message is padded with a '1' bit, followed by '0' bits, and finally, the original message length, to make its total length a multiple of 512 bits.

-   **Compression Function:** This is the core of the algorithm. It's an 80-round loop that scrambles the data using a series of bitwise logical operations (`Ch`, `Maj`), rotations, and additions, mixing in the "message schedule" and round constants.
