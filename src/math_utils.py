# This file contains core mathematical functions, primarily for number theory
# used in the RSA algorithm.

import random

def pow_mod(a: int, b: int, m: int) -> int:
    """
    Computes (a^b) % m efficiently using the method of repeated squares.
    This is equivalent to Python's built-in pow(a, b, m).
    """
    res = 1
    a %= m
    while b > 0:
        if b % 2 == 1:
            res = (res * a) % m
        a = (a * a) % m
        b //= 2
    return res

def _is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Probabilistic Miller-Rabin primality test.
    Returns True if n is *probably* prime, False if it is composite.
    k is the number of rounds of testing to perform.
    """
    if n == 2 or n == 3:
        return True
    if n < 5 or n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow_mod(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            # If the loop finished without finding n-1, n is composite
            return False

    # n is probably prime
    return True

def generate_prime(bits: int) -> int:
    """
    Generates a prime number of specified bit length.
    """
    while True:
        # Generate a random number of the correct bit length
        # Ensure it's odd and has the high bit set
        p = random.randrange(1 << (bits - 1), 1 << bits)
        if p % 2 == 0:
            p += 1
            
        if _is_prime_miller_rabin(p):
            return p

def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a: int, m: int) -> int:
    """
    Finds the modular multiplicative inverse of a modulo m.
    Returns x such that (a * x) % m = 1
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m
