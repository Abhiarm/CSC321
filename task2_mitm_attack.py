#!/usr/bin/env python3
"""
Task 2: MITM Key Fixing & Negotiated Groups
=============================================
Demonstrates two attacks on Diffie-Hellman:
  Part 1 — Mallory replaces Y_A and Y_B with q  (key fixing)
  Part 2 — Mallory tampers with the generator a  (negotiated groups)
"""

import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ── Helpers (same as Task 1) ─────────────────────────────────────────

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
    return h.digest()[:16]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ── IETF 1024-bit parameters ────────────────────────────────────────

Q = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371",
    16,
)

A = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5",
    16,
)

IV = b'\x00' * 16  # shared initialization vector


# =====================================================================
# Part 1 — MITM Key Fixing: Mallory replaces Y_A → q and Y_B → q
# =====================================================================

def mitm_key_fixing(q: int, a: int):
    print("=" * 70)
    print("  Task 2 Part 1 — MITM Key Fixing (Y_A → q, Y_B → q)")
    print("=" * 70)

    # ── Alice generates her key pair normally ──
    X_A = secrets.randbelow(q - 2) + 2
    Y_A = pow(a, X_A, q)
    print(f"\nAlice:")
    print(f"  X_A = {X_A}")
    print(f"  Y_A = {Y_A}")

    # ── Bob generates his key pair normally ──
    X_B = secrets.randbelow(q - 2) + 2
    Y_B = pow(a, X_B, q)
    print(f"\nBob:")
    print(f"  X_B = {X_B}")
    print(f"  Y_B = {Y_B}")

    # ── Mallory intercepts and replaces both public values with q ──
    Y_A_to_bob = q    # Mallory sends q to Bob instead of Y_A
    Y_B_to_alice = q  # Mallory sends q to Alice instead of Y_B
    print(f"\nMallory intercepts:")
    print(f"  Replaces Y_A → q (sends q to Bob)")
    print(f"  Replaces Y_B → q (sends q to Alice)")

    # ── Alice computes her shared secret using the tampered Y_B ──
    s_alice = pow(Y_B_to_alice, X_A, q)   # q^X_A mod q = 0
    k_alice = derive_key(s_alice)
    print(f"\nAlice computes:")
    print(f"  s = (received Y_B)^X_A mod q = q^X_A mod q = {s_alice}")
    print(f"  k = SHA256(s)[:16] = {k_alice.hex()}")

    # ── Bob computes his shared secret using the tampered Y_A ──
    s_bob = pow(Y_A_to_bob, X_B, q)       # q^X_B mod q = 0
    k_bob = derive_key(s_bob)
    print(f"\nBob computes:")
    print(f"  s = (received Y_A)^X_B mod q = q^X_B mod q = {s_bob}")
    print(f"  k = SHA256(s)[:16] = {k_bob.hex()}")

    assert s_alice == s_bob == 0, "Expected s = 0 for both!"
    print(f"\n  ✓ Both shared secrets = 0 (as Mallory predicted)")

    # ── Mallory knows s = 0, derives the same key ──
    s_mallory = 0
    k_mallory = derive_key(s_mallory)
    print(f"\nMallory knows s = 0:")
    print(f"  k_mallory = SHA256(0)[:16] = {k_mallory.hex()}")
    assert k_mallory == k_alice == k_bob
    print(f"  ✓ Mallory's key matches Alice's and Bob's key")

    # ── Alice encrypts "Hi Bob!" → c0 ──
    m0 = b"Hi Bob!"
    c0 = aes_cbc_encrypt(k_alice, IV, m0)
    print(f"\nAlice → Bob:")
    print(f"  m0 = {m0.decode()}")
    print(f"  c0 = {c0.hex()}")

    # ── Bob encrypts "Hi Alice!" → c1 ──
    m1 = b"Hi Alice!"
    c1 = aes_cbc_encrypt(k_bob, IV, m1)
    print(f"\nBob → Alice:")
    print(f"  m1 = {m1.decode()}")
    print(f"  c1 = {c1.hex()}")

    # ── Mallory decrypts both ciphertexts ──
    m0_mallory = aes_cbc_decrypt(k_mallory, IV, c0)
    m1_mallory = aes_cbc_decrypt(k_mallory, IV, c1)
    print(f"\nMallory decrypts:")
    print(f"  c0 → {m0_mallory.decode()}")
    print(f"  c1 → {m1_mallory.decode()}")
    assert m0_mallory == m0 and m1_mallory == m1
    print(f"  ✓ Mallory successfully recovered both plaintext messages!")

    print()


# =====================================================================
# Part 2 — Generator Tampering: Mallory replaces a with 1, q, or q-1
# =====================================================================

def mitm_generator_tamper(q: int, a_original: int, a_tampered: int, label: str):
    """
    Run DH with a tampered generator, then show Mallory can recover messages.
    """
    print("=" * 70)
    print(f"  Task 2 Part 2 — Generator Tamper: a → {label}")
    print("=" * 70)

    a = a_tampered  # Alice and Bob unknowingly use the tampered generator

    # ── Alice generates her key pair ──
    X_A = secrets.randbelow(q - 2) + 2
    Y_A = pow(a, X_A, q)
    print(f"\nAlice (using tampered a):")
    print(f"  X_A = {X_A}")
    print(f"  Y_A = a^X_A mod q = {Y_A}")

    # ── Bob generates his key pair ──
    X_B = secrets.randbelow(q - 2) + 2
    Y_B = pow(a, X_B, q)
    print(f"\nBob (using tampered a):")
    print(f"  X_B = {X_B}")
    print(f"  Y_B = a^X_B mod q = {Y_B}")

    # ── Both compute shared secret normally ──
    s_alice = pow(Y_B, X_A, q)
    s_bob   = pow(Y_A, X_B, q)
    k_alice = derive_key(s_alice)
    k_bob   = derive_key(s_bob)

    print(f"\nShared secret:")
    print(f"  Alice: s = {s_alice}")
    print(f"  Bob:   s = {s_bob}")
    assert s_alice == s_bob, "Shared secrets should match"
    print(f"  ✓ Shared secrets match: s = {s_alice}")
    print(f"  k = {k_alice.hex()}")

    # ── Alice encrypts m0, Bob encrypts m1 ──
    m0 = b"Hi Bob!"
    c0 = aes_cbc_encrypt(k_alice, IV, m0)
    m1 = b"Hi Alice!"
    c1 = aes_cbc_encrypt(k_bob, IV, m1)
    print(f"\nAlice → Bob:  c0 = {c0.hex()}")
    print(f"Bob → Alice:  c1 = {c1.hex()}")

    # ── Mallory's attack: determine possible s values ──
    # Depending on the tampered generator:
    #   a = 1       → Y = 1, s = 1
    #   a = q       → Y = 0, s = 0
    #   a = q-1     → Y ∈ {1, q-1}, s ∈ {1, q-1}
    if a_tampered == 1:
        candidates = [1]
        explanation = "a=1 ⟹ Y_A=Y_B=1 ⟹ s = 1^X mod q = 1"
    elif a_tampered == q:
        candidates = [0]
        explanation = "a=q ⟹ Y_A=Y_B=0 ⟹ s = 0^X mod q = 0"
    elif a_tampered == q - 1:
        candidates = [1, q - 1]
        explanation = ("a=q-1 ⟹ Y ∈ {1, q-1} ⟹ s ∈ {1, q-1}; "
                       "Mallory tries both")
    else:
        candidates = []
        explanation = "Unknown tampered value"

    print(f"\nMallory's reasoning:")
    print(f"  {explanation}")
    print(f"  Candidate shared secrets: {candidates}")

    # ── Mallory brute-forces the (small) candidate set ──
    recovered_m0 = None
    recovered_m1 = None
    for s_guess in candidates:
        k_guess = derive_key(s_guess)
        try:
            recovered_m0 = aes_cbc_decrypt(k_guess, IV, c0)
            recovered_m1 = aes_cbc_decrypt(k_guess, IV, c1)
            print(f"\n  s = {s_guess} → k = {k_guess.hex()}")
            print(f"    c0 decrypts to: {recovered_m0.decode()}")
            print(f"    c1 decrypts to: {recovered_m1.decode()}")
            print(f"    ✓ Mallory recovered both messages!")
            break
        except (ValueError, UnicodeDecodeError):
            print(f"  s = {s_guess} → decryption failed (wrong key), trying next…")

    assert recovered_m0 == m0 and recovered_m1 == m1, \
        "Mallory failed to recover messages!"

    print()


# =====================================================================
# Main
# =====================================================================

if __name__ == "__main__":

    # ── Part 1: Key Fixing Attack ──
    mitm_key_fixing(Q, A)

    # ── Part 2: Generator Tampering ──
    # Case 1: a = 1
    mitm_generator_tamper(Q, A, a_tampered=1, label="1")

    # Case 2: a = q
    mitm_generator_tamper(Q, A, a_tampered=Q, label="q")

    # Case 3: a = q - 1
    mitm_generator_tamper(Q, A, a_tampered=Q - 1, label="q-1")