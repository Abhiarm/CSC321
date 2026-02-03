#!/usr/bin/env python3
"""
Task 1: Exploring Pseudo-Randomness and Collision Resistance
This module implements SHA256 hashing with truncation and collision finding.
"""

import hashlib
import time
import random
import string
from typing import Tuple, Dict, List
import matplotlib.pyplot as plt


def sha256_hash(data: bytes) -> str:
    """Hash data using SHA256 and return hex digest."""
    return hashlib.sha256(data).hexdigest()


def sha256_hash_truncated(data: bytes, bits: int) -> str:
    """
    Hash data using SHA256 and return truncated digest.
    
    Args:
        data: Input bytes to hash
        bits: Number of bits to keep (8-50)
    
    Returns:
        Truncated hash as hex string
    """
    full_hash = hashlib.sha256(data).digest()
    # Convert to integer, truncate, and return
    hash_int = int.from_bytes(full_hash, 'big')
    # Keep only the specified number of bits
    truncated = hash_int >> (256 - bits)
    # Calculate hex length needed
    hex_len = (bits + 3) // 4
    return format(truncated, f'0{hex_len}x')


def hamming_distance_bits(s1: bytes, s2: bytes) -> int:
    """Calculate Hamming distance in bits between two byte strings."""
    if len(s1) != len(s2):
        raise ValueError("Strings must be of equal length")
    
    distance = 0
    for b1, b2 in zip(s1, s2):
        xor = b1 ^ b2
        distance += bin(xor).count('1')
    return distance


def create_string_pair_with_hamming_1() -> Tuple[bytes, bytes]:
    """Create two strings with Hamming distance of exactly 1 bit."""
    # Start with a random string
    base = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    base_bytes = base.encode()
    
    # Flip one bit in the last byte
    modified = bytearray(base_bytes)
    modified[-1] ^= 1  # Flip the least significant bit
    
    return base_bytes, bytes(modified)


def task_1a_demo():
    """Demonstrate SHA256 hashing of arbitrary inputs."""
    print("=" * 60)
    print("Task 1a: SHA256 Hashing Demo")
    print("=" * 60)
    
    test_inputs = [
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        b"password123",
        b"a",
        b"",
    ]
    
    for data in test_inputs:
        digest = sha256_hash(data)
        print(f"Input: {data.decode() if data else '(empty)'}")
        print(f"SHA256: {digest}")
        print()


def task_1b_demo():
    """Demonstrate hashing strings with Hamming distance of 1 bit."""
    print("=" * 60)
    print("Task 1b: Hamming Distance of 1 Bit")
    print("=" * 60)
    
    for i in range(5):
        s1, s2 = create_string_pair_with_hamming_1()
        h1 = sha256_hash(s1)
        h2 = sha256_hash(s2)
        
        # Calculate how many bytes differ in the hashes
        h1_bytes = bytes.fromhex(h1)
        h2_bytes = bytes.fromhex(h2)
        bytes_different = sum(1 for a, b in zip(h1_bytes, h2_bytes) if a != b)
        bits_different = hamming_distance_bits(h1_bytes, h2_bytes)
        
        print(f"Pair {i + 1}:")
        print(f"  String 1: {s1}")
        print(f"  String 2: {s2}")
        print(f"  Hamming distance (input): {hamming_distance_bits(s1, s2)} bit(s)")
        print(f"  Hash 1: {h1}")
        print(f"  Hash 2: {h2}")
        print(f"  Bytes different in hash: {bytes_different}/32")
        print(f"  Bits different in hash: {bits_different}/256")
        print()


def find_collision_birthday(bits: int) -> Tuple[bytes, bytes, int, float]:
    """
    Find a collision using birthday attack method.
    
    Args:
        bits: Number of bits in truncated hash
    
    Returns:
        Tuple of (message1, message2, num_hashes, time_taken)
    """
    start_time = time.time()
    seen: Dict[str, bytes] = {}
    counter = 0
    
    while True:
        # Generate random message
        msg = str(counter).encode() + random.randbytes(8)
        truncated_hash = sha256_hash_truncated(msg, bits)
        
        if truncated_hash in seen:
            elapsed = time.time() - start_time
            return seen[truncated_hash], msg, counter + 1, elapsed
        
        seen[truncated_hash] = msg
        counter += 1
        
        # Safety limit
        if counter > 2 ** (bits + 2):
            raise RuntimeError(f"Could not find collision in {counter} attempts")


def find_collision_target(bits: int) -> Tuple[bytes, bytes, int, float]:
    """
    Find a collision using target hash method (weak collision resistance).
    
    Args:
        bits: Number of bits in truncated hash
    
    Returns:
        Tuple of (message1, message2, num_hashes, time_taken)
    """
    start_time = time.time()
    
    # Fixed target message
    target_msg = b"target_message"
    target_hash = sha256_hash_truncated(target_msg, bits)
    
    counter = 0
    while True:
        # Generate candidate message
        msg = str(counter).encode()
        if msg != target_msg:
            candidate_hash = sha256_hash_truncated(msg, bits)
            
            if candidate_hash == target_hash:
                elapsed = time.time() - start_time
                return target_msg, msg, counter + 1, elapsed
        
        counter += 1
        
        # Safety limit
        if counter > 2 ** (bits + 2):
            raise RuntimeError(f"Could not find collision in {counter} attempts")


def task_1c_collision_analysis():
    """
    Find collisions for various digest sizes and measure performance.
    Uses birthday attack method.
    """
    print("=" * 60)
    print("Task 1c: Collision Finding Analysis (Birthday Attack)")
    print("=" * 60)
    
    results: List[Tuple[int, int, float, bytes, bytes, str]] = []
    
    # Test digest sizes from 8 to 50 bits in increments of 2
    for bits in range(8, 52, 2):
        print(f"\nFinding collision for {bits}-bit digest...")
        
        try:
            m1, m2, num_hashes, elapsed = find_collision_birthday(bits)
            
            # Verify collision
            h1 = sha256_hash_truncated(m1, bits)
            h2 = sha256_hash_truncated(m2, bits)
            assert h1 == h2, "Collision verification failed!"
            assert m1 != m2, "Messages should be different!"
            
            results.append((bits, num_hashes, elapsed, m1, m2, h1))
            print(f"  Collision found!")
            print(f"  Message 1: {m1[:50]}...")
            print(f"  Message 2: {m2[:50]}...")
            print(f"  Hash: {h1}")
            print(f"  Number of hashes: {num_hashes:,}")
            print(f"  Time: {elapsed:.4f} seconds")
            print(f"  Expected (2^(n/2)): {2**(bits/2):,.0f}")
            
        except Exception as e:
            print(f"  Error: {e}")
            break
    
    return results


def plot_results(results: List[Tuple[int, int, float, bytes, bytes, str]]):
    """Generate plots for collision analysis results."""
    if not results:
        print("No results to plot.")
        return
    
    bits = [r[0] for r in results]
    num_hashes = [r[1] for r in results]
    times = [r[2] for r in results]
    
    # Expected values based on birthday bound
    expected_hashes = [2 ** (b / 2) for b in bits]
    
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Plot 1: Digest size vs Number of inputs
    ax1.semilogy(bits, num_hashes, 'b-o', label='Actual', linewidth=2, markersize=6)
    ax1.semilogy(bits, expected_hashes, 'r--', label='Expected (2^(n/2))', linewidth=2)
    ax1.set_xlabel('Digest Size (bits)', fontsize=12)
    ax1.set_ylabel('Number of Hashes (log scale)', fontsize=12)
    ax1.set_title('Digest Size vs Number of Inputs to Find Collision', fontsize=14)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Digest size vs Time
    ax2.semilogy(bits, times, 'g-o', linewidth=2, markersize=6)
    ax2.set_xlabel('Digest Size (bits)', fontsize=12)
    ax2.set_ylabel('Time (seconds, log scale)', fontsize=12)
    ax2.set_title('Digest Size vs Time to Find Collision', fontsize=14)
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('Module4/collision_analysis.png', dpi=150)
    print("\nPlots saved to Module4/collision_analysis.png")
    plt.close()


def save_results_to_file(results: List[Tuple[int, int, float, bytes, bytes, str]]):
    """Save collision analysis results to a CSV file."""
    with open('Module4/collision_results.csv', 'w') as f:
        f.write("Digest_Bits,Num_Hashes,Time_Seconds,Expected_Hashes\n")
        for bits, num_hashes, elapsed, m1, m2, hash_val in results:
            expected = 2 ** (bits / 2)
            f.write(f"{bits},{num_hashes},{elapsed:.6f},{expected:.0f}\n")
    print("Results saved to Module4/collision_results.csv")
    
    # Save collision examples to a separate file
    with open('Module4/collision_examples.csv', 'w') as f:
        f.write("Digest_Bits,Hash,Message1_Hex,Message2_Hex\n")
        for bits, num_hashes, elapsed, m1, m2, hash_val in results:
            m1_hex = m1.hex()
            m2_hex = m2.hex()
            f.write(f"{bits},{hash_val},{m1_hex},{m2_hex}\n")
    print("Collision examples saved to Module4/collision_examples.csv")


def main():
    """Main function to run all Task 1 demonstrations."""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHIC HASH FUNCTIONS - TASK 1")
    print("=" * 60 + "\n")
    
    # Task 1a: Basic SHA256 hashing
    task_1a_demo()
    
    # Task 1b: Hamming distance exploration
    task_1b_demo()
    
    # Task 1c: Collision finding analysis
    print("\nStarting collision analysis (this may take a while)...")
    print("Press Ctrl+C to stop early.\n")
    
    try:
        results = task_1c_collision_analysis()
        
        if results:
            save_results_to_file(results)
            plot_results(results)
            
            # Summary statistics
            print("\n" + "=" * 60)
            print("SUMMARY")
            print("=" * 60)
            print(f"Total digest sizes tested: {len(results)}")
            print(f"Digest range: {results[0][0]} to {results[-1][0]} bits")
            
            # Estimate time for full 256-bit collision
            if len(results) >= 3:
                # Use last few data points to estimate growth rate
                last_bits = results[-1][0]
                last_time = results[-1][2]
                # Time roughly doubles for each 2 bits
                bits_remaining = 256 - last_bits
                estimated_time = last_time * (2 ** (bits_remaining / 2))
                years = estimated_time / (365.25 * 24 * 3600)
                print(f"\nEstimated time for 256-bit collision: {years:.2e} years")
    
    except KeyboardInterrupt:
        print("\n\nCollision analysis interrupted by user.")


if __name__ == "__main__":
    main()