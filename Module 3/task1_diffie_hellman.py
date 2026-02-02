#!/usr/bin/env python3
"""
Task 1: Diffie-Hellman Key Exchange Implementation
===================================================
Emulates the full DH key exchange protocol between Alice and Bob.
- First with small parameters (q=37, a=5)
- Then with IETF 1024-bit parameters
"""

import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


def int_to_bytes(n: int) -> bytes:
    """Convert a non-negative integer to a big-endian byte string."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def derive_key(shared_secret: int) -> bytes:
    """Derive a 16-byte AES key from the shared secret using SHA-256."""
    h = SHA256.new()
    h.update(int_to_bytes(shared_secret))
    return h.digest()[:16]  # truncate to 16 bytes for AES-128


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-CBC, applying PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES-CBC, removing PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def diffie_hellman_exchange(q: int, a: int, label: str = ""):
    """
    Run the full Diffie-Hellman key exchange between Alice and Bob.

    Parameters
    ----------
    q : int  — the prime modulus
    a : int  — the generator
    label : str — descriptive label for output
    """
    print("=" * 70)
    print(f"  Diffie-Hellman Key Exchange — {label}")
    print("=" * 70)

    # --- Public parameters ---
    print(f"\nPublic parameters:")
    print(f"  q = {q}")
    print(f"  a = {a}")

    # --- Alice picks a random private key X_A ∈ {2, ..., q-2} ---
    X_A = secrets.randbelow(q - 2) + 2  # range [2, q-1)
    Y_A = pow(a, X_A, q)

    print(f"\nAlice:")
    print(f"  Private key  X_A = {X_A}")
    print(f"  Public value Y_A = a^X_A mod q = {Y_A}")

    # --- Bob picks a random private key X_B ∈ {2, ..., q-2} ---
    X_B = secrets.randbelow(q - 2) + 2
    Y_B = pow(a, X_B, q)

    print(f"\nBob:")
    print(f"  Private key  X_B = {X_B}")
    print(f"  Public value Y_B = a^X_B mod q = {Y_B}")

    # --- Exchange public values and compute shared secret ---
    # Alice sends Y_A to Bob; Bob sends Y_B to Alice.
    s_alice = pow(Y_B, X_A, q)
    s_bob   = pow(Y_A, X_B, q)

    print(f"\nShared secret computation:")
    print(f"  Alice computes s = Y_B^X_A mod q = {s_alice}")
    print(f"  Bob   computes s = Y_A^X_B mod q = {s_bob}")
    assert s_alice == s_bob, "ERROR: shared secrets do not match!"
    print(f"  ✓ Shared secrets match: s = {s_alice}")

    # --- Derive symmetric key ---
    k_alice = derive_key(s_alice)
    k_bob   = derive_key(s_bob)

    print(f"\nDerived AES-128 key (SHA-256 truncated to 16 bytes):")
    print(f"  Alice: k = {k_alice.hex()}")
    print(f"  Bob:   k = {k_bob.hex()}")
    assert k_alice == k_bob, "ERROR: derived keys do not match!"
    print(f"  ✓ Keys match")

    # --- Encrypted message exchange ---
    # Use a shared initialization vector (16 zero bytes for simplicity)
    iv = b'\x00' * 16

    # Alice encrypts m0 = "Hi Bob!" and sends c0 to Bob
    m0 = b"Hi Bob!"
    c0 = aes_cbc_encrypt(k_alice, iv, m0)
    print(f"\nAlice → Bob:")
    print(f"  Plaintext  m0 = {m0.decode()}")
    print(f"  Ciphertext c0 = {c0.hex()}")

    # Bob decrypts c0
    m0_dec = aes_cbc_decrypt(k_bob, iv, c0)
    print(f"  Bob decrypts:  {m0_dec.decode()}")
    assert m0_dec == m0, "ERROR: Bob failed to decrypt Alice's message!"
    print(f"  ✓ Bob successfully decrypted Alice's message")

    # Bob encrypts m1 = "Hi Alice!" and sends c1 to Alice
    m1 = b"Hi Alice!"
    c1 = aes_cbc_encrypt(k_bob, iv, m1)
    print(f"\nBob → Alice:")
    print(f"  Plaintext  m1 = {m1.decode()}")
    print(f"  Ciphertext c1 = {c1.hex()}")

    # Alice decrypts c1
    m1_dec = aes_cbc_decrypt(k_alice, iv, c1)
    print(f"  Alice decrypts: {m1_dec.decode()}")
    assert m1_dec == m1, "ERROR: Alice failed to decrypt Bob's message!"
    print(f"  ✓ Alice successfully decrypted Bob's message")

    print()


# ============================================================
# Main — run with both parameter sets
# ============================================================
if __name__ == "__main__":

    # ----------------------------------------------------------
    # Part A: Small group  q = 37, a = 5
    # ----------------------------------------------------------
    diffie_hellman_exchange(q=37, a=5, label="Small group (q=37, a=5)")

    # ----------------------------------------------------------
    # Part B: IETF 1024-bit parameters
    # ----------------------------------------------------------
    q_ietf = int(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371",
        16
    )

    a_ietf = int(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5",
        16
    )

    diffie_hellman_exchange(q=q_ietf, a=a_ietf,
                            label="IETF 1024-bit parameters")