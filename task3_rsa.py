#!/usr/bin/env python3
"""
Task 3: "Textbook" RSA & MITM Key Fixing via Malleability
==========================================================
Part 1 — Textbook RSA: key generation, encryption, decryption
Part 2 — MITM attack exploiting RSA malleability + signature forgery
"""

import secrets
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ── Helpers ──────────────────────────────────────────────────────────

def int_to_bytes(n: int) -> bytes:
    """Convert a non-negative integer to a big-endian byte string."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """Convert a big-endian byte string to an integer."""
    return int.from_bytes(b, byteorder='big')


def derive_key(value: int) -> bytes:
    """Derive a 16-byte AES key from an integer using SHA-256."""
    h = SHA256.new()
    h.update(int_to_bytes(value))
    return h.digest()[:16]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


IV = b'\x00' * 16  # shared initialization vector


# =====================================================================
# Part 1 — Textbook RSA Implementation
# =====================================================================

def extended_gcd(a: int, b: int):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Compute the modular multiplicative inverse of e modulo phi
    using the Extended Euclidean Algorithm.
    Returns d such that (e * d) mod phi = 1.
    Raises ValueError if inverse does not exist.
    """
    gcd, x, _ = extended_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={gcd})")
    return x % phi


def rsa_keygen(bits: int = 2048, e: int = 65537):
    """
    Generate an RSA key pair.

    Parameters
    ----------
    bits : int — bit length of each prime (n will be ~2*bits bits)
    e    : int — public exponent (default 65537)

    Returns
    -------
    (pub, pri) where pub = (n, e) and pri = (n, d)
    """
    while True:
        p = getPrime(bits)
        q = getPrime(bits)
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)  # Euler's totient

    # Verify gcd(e, phi) == 1  (almost always true for e=65537)
    g, _, _ = extended_gcd(e, phi)
    assert g == 1, "e and phi(n) are not coprime; regenerate primes"

    d = mod_inverse(e, phi)

    # Sanity check
    assert (e * d) % phi == 1, "Key generation error: e*d != 1 mod phi"

    return (n, e), (n, d)


def rsa_encrypt(pub: tuple, m: int) -> int:
    """Textbook RSA encryption: c = m^e mod n."""
    n, e = pub
    assert 0 <= m < n, "Message must be in Z*_n (i.e., 0 <= m < n)"
    return pow(m, e, n)


def rsa_decrypt(pri: tuple, c: int) -> int:
    """Textbook RSA decryption: m = c^d mod n."""
    n, d = pri
    return pow(c, d, n)


def demo_textbook_rsa():
    """Demonstrate textbook RSA key generation, encryption, and decryption."""
    print("=" * 70)
    print("  Task 3 Part 1 — Textbook RSA")
    print("=" * 70)

    # Generate a 1024-bit key pair (each prime ~1024 bits → n ~2048 bits)
    print("\nGenerating RSA key pair (1024-bit primes, e=65537)...")
    pub, pri = rsa_keygen(bits=1024)
    n, e = pub
    _, d = pri
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"  d = {d}")
    print(f"  n bit-length = {n.bit_length()} bits")

    # Encrypt and decrypt a few messages
    messages = [
        "Hello, RSA!",
        "Textbook RSA is insecure.",
        "CSC321 Public Key Crypto",
    ]

    print(f"\n--- Encrypting and decrypting messages ---")
    for msg_str in messages:
        # Convert string → bytes → integer
        msg_bytes = msg_str.encode('utf-8')
        m = bytes_to_int(msg_bytes)
        assert m < n, "Message too large for this key!"

        c = rsa_encrypt(pub, m)
        m_dec = rsa_decrypt(pri, c)
        msg_dec = int_to_bytes(m_dec).decode('utf-8')

        print(f"\n  Plaintext:  \"{msg_str}\"")
        print(f"  m (int):    {m}")
        print(f"  Ciphertext: {c}")
        print(f"  Decrypted:  \"{msg_dec}\"")
        assert msg_dec == msg_str, "Decryption failed!"
        print(f"  ✓ Decryption successful")

    print()
    return pub, pri


# =====================================================================
# Part 2 — MITM Attack via RSA Malleability
# =====================================================================

def demo_malleability_attack(pub, pri):
    """
    Demonstrate the MITM attack on textbook RSA key exchange.

    Protocol:
      1. Alice publishes (n, e)
      2. Bob picks random s ∈ Z*_n, sends c = s^e mod n
      3. Mallory intercepts c, sends c' to Alice
      4. Alice decrypts s' = (c')^d mod n, derives k = SHA256(s')
      5. Alice encrypts m = "Hi Bob!" with AES-CBC_k and sends c0
      6. Mallory decrypts c0 using k (since she chose c' to know s')

    Attack: Mallory picks her own value r, computes c' = r^e mod n.
    When Alice decrypts c', she gets s' = r. Mallory knows r, so she
    can derive k = SHA256(r) and decrypt Alice's message.
    """
    print("=" * 70)
    print("  Task 3 Part 2 — MITM Attack via RSA Malleability")
    print("=" * 70)

    n, e = pub
    _, d = pri

    # ── Bob picks random s, computes c = s^e mod n ──
    s_bob = secrets.randbelow(n - 2) + 2  # s ∈ Z*_n
    c = rsa_encrypt(pub, s_bob)
    print(f"\nBob:")
    print(f"  Picks random s = {s_bob}")
    print(f"  Sends c = s^e mod n = {c}")

    # ── Mallory intercepts c and crafts c' ──
    # Mallory picks her own r and computes c' = r^e mod n
    # When Alice decrypts c', she gets s' = r
    r = secrets.randbelow(n - 2) + 2  # Mallory's chosen value
    c_prime = rsa_encrypt(pub, r)  # c' = r^e mod n
    print(f"\nMallory intercepts c and crafts c':")
    print(f"  Mallory picks r = {r}")
    print(f"  Mallory computes c' = r^e mod n = {c_prime}")
    print(f"  Mallory sends c' to Alice (instead of c)")

    # ── Alice decrypts c' to get s' ──
    s_prime = rsa_decrypt(pri, c_prime)  # s' = (c')^d mod n = r
    k_alice = derive_key(s_prime)
    print(f"\nAlice:")
    print(f"  Decrypts c' → s' = {s_prime}")
    print(f"  Derives k = SHA256(s')[:16] = {k_alice.hex()}")

    # Verify Alice recovered Mallory's r
    assert s_prime == r, "s' should equal r"
    print(f"  (s' == r: ✓)")

    # ── Alice encrypts a message ──
    m = b"Hi Bob!"
    c0 = aes_cbc_encrypt(k_alice, IV, m)
    print(f"\n  Alice encrypts m = \"{m.decode()}\"")
    print(f"  c0 = {c0.hex()}")

    # ── Mallory decrypts c0 ──
    # Mallory knows r, so she can compute k = SHA256(r)[:16]
    k_mallory = derive_key(r)
    m_mallory = aes_cbc_decrypt(k_mallory, IV, c0)
    print(f"\nMallory:")
    print(f"  Knows r = {r}")
    print(f"  Derives k = SHA256(r)[:16] = {k_mallory.hex()}")
    print(f"  Decrypts c0 → \"{m_mallory.decode()}\"")
    assert m_mallory == m
    print(f"  ✓ Mallory successfully recovered the plaintext message!")

    print()


# =====================================================================
# Signature Malleability Demonstration
# =====================================================================

def demo_signature_malleability(pub, pri):
    """
    Demonstrate RSA signature malleability.

    Sign(m, d) = m^d mod n

    If Mallory sees signatures for m1 and m2:
      sig1 = m1^d mod n
      sig2 = m2^d mod n

    Then she can forge a signature for m3 = m1 * m2 mod n:
      sig3 = sig1 * sig2 mod n
           = (m1^d) * (m2^d) mod n
           = (m1 * m2)^d mod n
           = Sign(m1 * m2, d)
    """
    print("=" * 70)
    print("  Task 3 Part 2 — RSA Signature Malleability")
    print("=" * 70)

    n, e = pub
    _, d = pri

    # Two messages (as integers)
    m1 = bytes_to_int(b"msg_one")
    m2 = bytes_to_int(b"msg_two")
    m3 = (m1 * m2) % n  # The forged message

    # Legitimate signatures
    sig1 = pow(m1, d, n)  # Sign(m1, d)
    sig2 = pow(m2, d, n)  # Sign(m2, d)

    print(f"\nLegitimate signatures:")
    print(f"  m1 = {m1}  (\"msg_one\")")
    print(f"  m2 = {m2}  (\"msg_two\")")
    print(f"  sig1 = m1^d mod n = {sig1}")
    print(f"  sig2 = m2^d mod n = {sig2}")

    # Verify legitimate signatures
    assert pow(sig1, e, n) == m1, "sig1 verification failed"
    assert pow(sig2, e, n) == m2, "sig2 verification failed"
    print(f"\n  ✓ sig1 verifies: sig1^e mod n == m1")
    print(f"  ✓ sig2 verifies: sig2^e mod n == m2")

    # Mallory forges signature for m3 = m1 * m2 mod n
    sig3_forged = (sig1 * sig2) % n
    print(f"\nMallory forges signature for m3 = m1 * m2 mod n:")
    print(f"  m3 = {m3}")
    print(f"  sig3 = sig1 * sig2 mod n = {sig3_forged}")

    # Verify forged signature
    verified = pow(sig3_forged, e, n)
    print(f"\nVerification:")
    print(f"  sig3^e mod n = {verified}")
    print(f"  m3           = {m3}")
    assert verified == m3, "Forged signature verification failed!"
    print(f"  ✓ Forged signature is valid! sig3^e mod n == m3")

    # Compute legitimate signature for m3 to cross-check
    sig3_legit = pow(m3, d, n)
    assert sig3_forged == sig3_legit, "Forged sig doesn't match legitimate sig"
    print(f"  ✓ Forged signature matches the legitimate signature for m3")

    print()


# =====================================================================
# Main
# =====================================================================

if __name__ == "__main__":

    # Part 1: Textbook RSA
    pub, pri = demo_textbook_rsa()

    # Part 2: MITM attack via malleability
    demo_malleability_attack(pub, pri)

    # Part 2 (continued): Signature malleability
    demo_signature_malleability(pub, pri)