#!/usr/bin/env python3
"""
Task 2: Breaking Real Hashes (Bcrypt Password Cracker)
This module implements a custom bcrypt password cracker using the NLTK word corpus.

AI Citation: Claude (Anthropic) was used to assist with code generation and optimization.

Usage:
    python task2_bcrypt_cracker.py              # Run interactively (single core)
    python task2_bcrypt_cracker.py --test       # Test bcrypt setup
    python task2_bcrypt_cracker.py --background # Run in background, log to file
    python task2_bcrypt_cracker.py --parallel   # Use all CPU cores
    python task2_bcrypt_cracker.py --parallel 8 # Use 8 CPU cores
    python task2_bcrypt_cracker.py --parallel --background  # Parallel + background
    
    # To run in background and keep running after terminal closes:
    nohup python task2_bcrypt_cracker.py --parallel --background &
"""

import bcrypt
import time
import multiprocessing
from typing import Optional, Tuple, List, Dict, Any
from functools import partial
import os
import sys
from datetime import datetime


class Logger:
    """Logger that writes to both console and file."""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.file_handle = None
        if log_file:
            self.file_handle = open(log_file, 'a')
            
    def log(self, message: str, flush: bool = True):
        """Log message to console and file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        print(formatted, flush=flush)
        if self.file_handle:
            self.file_handle.write(formatted + "\n")
            if flush:
                self.file_handle.flush()
    
    def close(self):
        if self.file_handle:
            self.file_handle.close()


# Global logger instance
logger = Logger()


def save_progress(user: str, password: str, time_taken: float, attempts: int, workfactor: int):
    """Save a cracked password immediately to progress file."""
    with open('Module4/cracking_progress.txt', 'a') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {user}: {password} (time: {time_taken:.2f}s, attempts: {attempts}, wf: {workfactor})\n")


# Shadow file content (from provided PDF)
SHADOW_FILE_CONTENT = """Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq
Gandalf:$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC
Thorin:$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q
Fili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm
Kili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im
Balin:$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom
Dwalin:$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be
Oin:$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK
Gloin:$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q
Dori:$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq
Nori:$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12
Ori:$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O
Bifur:$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK
Bofur:$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O
Durin:$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"""


def parse_shadow_entry(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a shadow file entry into its components.
    
    Format: User:$Algorithm$Workfactor$SaltHash
    where salt is 22 characters base64 encoded and hash is the remainder.
    """
    if not line.strip():
        return None
    
    parts = line.strip().split(':')
    if len(parts) != 2:
        return None
    
    user = parts[0]
    full_hash = parts[1]
    hash_parts = full_hash.split('$')
    
    if len(hash_parts) < 4:
        return None
    
    # hash_parts[0] is empty (before first $)
    # hash_parts[1] is algorithm (2b)
    # hash_parts[2] is workfactor
    # hash_parts[3] is salt (22 chars) + hash (rest)
    
    algorithm = hash_parts[1]
    workfactor = int(hash_parts[2])
    salt_hash = hash_parts[3]
    salt = salt_hash[:22]
    hash_value = salt_hash[22:]
    
    # The salt for bcrypt.hashpw needs to include the prefix
    # Format: $2b$<workfactor>$<22-char-salt>
    bcrypt_salt = f"${algorithm}${hash_parts[2]}${salt}"
    
    return {
        'user': user,
        'algorithm': algorithm,
        'workfactor': workfactor,
        'salt': salt,
        'bcrypt_salt': bcrypt_salt,
        'hash': hash_value,
        'full_hash': full_hash
    }


def get_nltk_words(min_length: int = 6, max_length: int = 10) -> List[str]:
    """
    Get words from NLTK corpus filtered by length.
    Returns words between min_length and max_length (inclusive).
    """
    try:
        import nltk
        from nltk.corpus import words
        
        # Download words corpus if not present
        try:
            word_list = words.words()
        except LookupError:
            print("Downloading NLTK words corpus...")
            nltk.download('words', quiet=True)
            word_list = words.words()
        
        # Filter by length and convert to lowercase
        filtered_words = [
            w.lower() for w in word_list 
            if min_length <= len(w) <= max_length
        ]
        
        # Remove duplicates and sort
        filtered_words = sorted(list(set(filtered_words)))
        
        print(f"Loaded {len(filtered_words):,} words from NLTK corpus "
              f"(length {min_length}-{max_length})")
        
        return filtered_words
    
    except ImportError:
        print("NLTK not installed. Please install with: pip install nltk")
        raise


def check_password_hashpw(password: str, bcrypt_salt: str, expected_hash: str) -> bool:
    """
    Check if a password matches using hashpw method.
    
    Args:
        password: Plaintext password to test
        bcrypt_salt: The 29-character salt (e.g., $2b$08$J9FW66ZdPI2nrIMcOxFYI.)
        expected_hash: The full hash to compare against
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        computed_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt_salt.encode('utf-8'))
        return computed_hash.decode('utf-8') == expected_hash
    except Exception:
        return False


def check_password_checkpw(password: str, full_hash: str) -> bool:
    """
    Check if a password matches using checkpw method.
    
    Args:
        password: Plaintext password to test
        full_hash: The full bcrypt hash
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), full_hash.encode('utf-8'))
    except Exception:
        return False


def crack_single_user(user: str, full_hash: str, word_list: List[str], 
                      progress_interval: int = 5000) -> Optional[Tuple[str, float, int]]:
    """
    Crack a single user's password.
    
    Returns:
        Tuple of (password, time_taken, attempts) if found, None otherwise
    """
    start_time = time.time()
    
    for i, word in enumerate(word_list):
        if i > 0 and i % progress_interval == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"    [{user}] Tried {i:,} words ({rate:.1f} words/sec)...")
        
        if check_password_checkpw(word, full_hash):
            elapsed = time.time() - start_time
            return (word, elapsed, i + 1)
    
    return None


def crack_worker_chunk(args):
    """Worker function for parallel cracking. Checks a chunk of words against a hash."""
    word_chunk, full_hash, start_index = args
    for i, word in enumerate(word_chunk):
        try:
            if bcrypt.checkpw(word.encode('utf-8'), full_hash.encode('utf-8')):
                return (word, start_index + i)
        except:
            pass
    return None


def crack_user_parallel(user: str, full_hash: str, word_list: List[str], 
                        num_processes: int) -> Optional[Tuple[str, float, int]]:
    """Crack a single user's password using multiple processes."""
    from multiprocessing import Pool
    
    # Split word list into chunks for each process
    chunk_size = len(word_list) // num_processes
    if chunk_size == 0:
        chunk_size = 1
    
    args_list = []
    for i in range(num_processes):
        start = i * chunk_size
        end = start + chunk_size if i < num_processes - 1 else len(word_list)
        if start < len(word_list):
            args_list.append((word_list[start:end], full_hash, start))
    
    start_time = time.time()
    
    with Pool(processes=num_processes) as pool:
        results = pool.map(crack_worker_chunk, args_list)
    
    # Check results from all processes
    for result in results:
        if result is not None:
            password, word_idx = result
            elapsed = time.time() - start_time
            return (password, elapsed, word_idx + 1)
    
    return None


def crack_by_workfactor_group_parallel(entries: List[Dict], word_list: List[str], 
                                        num_processes: int = None) -> List[Dict[str, Any]]:
    """
    Crack passwords using multiple CPU cores.
    """
    import multiprocessing as mp
    
    if num_processes is None:
        num_processes = mp.cpu_count()
    
    results = []
    
    # Group by workfactor
    workfactor_groups: Dict[int, List[Dict]] = {}
    for entry in entries:
        wf = entry['workfactor']
        if wf not in workfactor_groups:
            workfactor_groups[wf] = []
        workfactor_groups[wf].append(entry)
    
    # Process each workfactor group
    for workfactor in sorted(workfactor_groups.keys()):
        group = workfactor_groups[workfactor]
        logger.log(f"\n{'='*70}")
        logger.log(f"CRACKING WORKFACTOR {workfactor} ({len(group)} users) - {num_processes} cores")
        logger.log(f"{'='*70}")
        
        start_time = time.time()
        
        # For each user, try to crack in parallel
        for entry in group:
            user = entry['user']
            logger.log(f"  Cracking {user}...")
            
            result = crack_user_parallel(user, entry['full_hash'], word_list, num_processes)
            
            if result is not None:
                password, elapsed, attempts = result
                logger.log(f"  [+] FOUND: {user}'s password is '{password}' "
                      f"(Time: {elapsed:.2f}s, Word index: {attempts:,})")
                results.append({
                    'user': user,
                    'password': password,
                    'time': elapsed,
                    'attempts': attempts,
                    'workfactor': workfactor
                })
                save_progress(user, password, elapsed, attempts, workfactor)
            else:
                elapsed = time.time() - start_time
                logger.log(f"  [-] NOT FOUND: {user}'s password")
                results.append({
                    'user': user,
                    'password': None,
                    'time': elapsed,
                    'attempts': len(word_list),
                    'workfactor': workfactor
                })
    
    return results


def crack_by_workfactor_group(entries: List[Dict], word_list: List[str]) -> List[Dict[str, Any]]:
    """
    Crack passwords grouped by workfactor for efficiency.
    Users with the same workfactor and salt can be checked together.
    """
    results = []
    
    # Group by workfactor
    workfactor_groups: Dict[int, List[Dict]] = {}
    for entry in entries:
        wf = entry['workfactor']
        if wf not in workfactor_groups:
            workfactor_groups[wf] = []
        workfactor_groups[wf].append(entry)
    
    # Process each workfactor group (starting with lowest)
    for workfactor in sorted(workfactor_groups.keys()):
        group = workfactor_groups[workfactor]
        logger.log(f"\n{'='*70}")
        logger.log(f"CRACKING WORKFACTOR {workfactor} ({len(group)} users)")
        logger.log(f"{'='*70}")
        
        # Track which users still need to be cracked
        remaining = {e['user']: e for e in group}
        
        start_time = time.time()
        
        for i, word in enumerate(word_list):
            if not remaining:
                break
                
            if i > 0 and i % 5000 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                logger.log(f"  Tried {i:,} words ({rate:.1f} words/sec), "
                      f"{len(remaining)} users remaining...")
            
            # Check this word against all remaining users in the group
            found_users = []
            for user, entry in remaining.items():
                if check_password_checkpw(word, entry['full_hash']):
                    elapsed = time.time() - start_time
                    logger.log(f"  [+] FOUND: {user}'s password is '{word}' "
                          f"(Time: {elapsed:.2f}s, Attempt: {i+1:,})")
                    results.append({
                        'user': user,
                        'password': word,
                        'time': elapsed,
                        'attempts': i + 1,
                        'workfactor': workfactor
                    })
                    # Save progress immediately
                    save_progress(user, word, elapsed, i + 1, workfactor)
                    found_users.append(user)
            
            # Remove found users from remaining
            for user in found_users:
                del remaining[user]
        
        # Mark any remaining users as not found
        for user, entry in remaining.items():
            elapsed = time.time() - start_time
            logger.log(f"  [-] NOT FOUND: {user}'s password (exhausted word list)")
            results.append({
                'user': user,
                'password': None,
                'time': elapsed,
                'attempts': len(word_list),
                'workfactor': workfactor
            })
    
    return results


def parse_shadow_file(filepath: str = None, content: str = None) -> List[Dict[str, Any]]:
    """Parse shadow file and return list of user entries."""
    entries = []
    
    if content:
        lines = content.strip().split('\n')
    elif filepath:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    else:
        raise ValueError("Must provide either filepath or content")
    
    for line in lines:
        entry = parse_shadow_entry(line)
        if entry:
            entries.append(entry)
    
    return entries


def estimate_time(workfactor: int, num_words: int) -> float:
    """
    Estimate time to crack based on workfactor.
    Based on M1 chip benchmarks from assignment.
    """
    # Approximate times per hash based on workfactor (in seconds)
    times_per_hash = {
        8: 0.030,   # 30 ms
        9: 0.060,   # 60 ms
        10: 0.110,  # 110 ms
        11: 0.220,  # 220 ms
        12: 0.420,  # 420 ms
        13: 0.840,  # 840 ms
    }
    
    time_per_hash = times_per_hash.get(workfactor, 0.5)
    total_seconds = time_per_hash * num_words
    return total_seconds


def verify_test_vector():
    """Verify the implementation with the provided test vector."""
    print("Verifying test vector...")
    
    # From the assignment hints
    result = bcrypt.hashpw(b"registrationsucks", b"$2b$08$J9FW66ZdPI2nrIMcOxFYI.")
    expected = b'$2b$08$J9FW66ZdPI2nrIMcOxFYI.zKGJsUXmWLAYWsNmIANUy5JbSjfyLFu'
    
    print(f"  Input: 'registrationsucks'")
    print(f"  Salt:  '$2b$08$J9FW66ZdPI2nrIMcOxFYI.'")
    print(f"  Result:   {result}")
    print(f"  Expected: {expected}")
    print(f"  Match: {result == expected}")
    
    return result == expected


def main(background_mode: bool = False, parallel: int = 0):
    """Main function to crack bcrypt passwords.
    
    Args:
        background_mode: If True, log to file
        parallel: Number of CPU cores to use (0 = single-threaded)
    """
    global logger
    
    # Set up logging
    if background_mode:
        log_file = f"Module4/cracking_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        logger = Logger(log_file)
        logger.log(f"Background mode enabled. Logging to: {log_file}")
        # Clear progress file
        with open('Module4/cracking_progress.txt', 'w') as f:
            f.write(f"=== Password Cracking Started: {datetime.now()} ===\n\n")
    
    logger.log("=" * 70)
    logger.log("TASK 2: BCRYPT PASSWORD CRACKER")
    logger.log("=" * 70)
    logger.log("\nAI Citation: Claude (Anthropic) was used to assist with code generation.\n")
    
    # Verify test vector first
    if not verify_test_vector():
        logger.log("ERROR: Test vector verification failed!")
        return
    logger.log("")
    
    # Parse shadow file
    logger.log("Parsing shadow file...")
    entries = parse_shadow_file(content=SHADOW_FILE_CONTENT)
    
    logger.log(f"\nFound {len(entries)} users to crack:")
    logger.log("-" * 70)
    logger.log(f"{'User':<12} {'Algorithm':<10} {'Workfactor':<12} {'Salt':<24}")
    logger.log("-" * 70)
    for entry in entries:
        logger.log(f"{entry['user']:<12} {entry['algorithm']:<10} {entry['workfactor']:<12} {entry['salt']:<24}")
    logger.log("")
    
    # Load word list
    logger.log("Loading word list...")
    word_list = get_nltk_words(min_length=6, max_length=10)
    logger.log("")
    
    # Estimate times
    logger.log("Estimated cracking times (worst case per user, sequential):")
    logger.log("-" * 70)
    for wf in sorted(set(e['workfactor'] for e in entries)):
        est_time = estimate_time(wf, len(word_list))
        hours = est_time / 3600
        count = len([e for e in entries if e['workfactor'] == wf])
        logger.log(f"  Workfactor {wf}: ~{hours:.1f} hours per user ({count} users)")
    logger.log("")
    
    # Crack passwords (grouped by workfactor)
    logger.log("\n" + "=" * 70)
    if parallel > 0:
        logger.log(f"STARTING PASSWORD CRACKING (PARALLEL - {parallel} cores)")
    else:
        logger.log("STARTING PASSWORD CRACKING (grouped by workfactor)")
    logger.log("=" * 70)
    
    total_start = time.time()
    if parallel > 0:
        results = crack_by_workfactor_group_parallel(entries, word_list, parallel)
    else:
        results = crack_by_workfactor_group(entries, word_list)
    total_time = time.time() - total_start
    
    # Summary
    logger.log("\n" + "=" * 70)
    logger.log("CRACKING SUMMARY")
    logger.log("=" * 70)
    logger.log(f"\n{'User':<12} {'Password':<20} {'Time (s)':<15} {'Workfactor':<12}")
    logger.log("-" * 70)
    
    for r in sorted(results, key=lambda x: (x['workfactor'], x['user'])):
        password = r['password'] if r['password'] else 'NOT FOUND'
        time_str = f"{r['time']:.2f}" if r['time'] else 'N/A'
        logger.log(f"{r['user']:<12} {password:<20} {time_str:<15} {r['workfactor']:<12}")
    
    logger.log("-" * 70)
    cracked = len([r for r in results if r['password']])
    logger.log(f"Cracked: {cracked}/{len(results)} passwords")
    logger.log(f"Total time: {total_time:.2f} seconds ({total_time/60:.2f} minutes, "
          f"{total_time/3600:.2f} hours)")
    
    # Save results
    save_results(results, total_time)
    
    if background_mode:
        logger.log(f"\n=== Completed at {datetime.now()} ===")
        logger.close()
    
    return results


def save_results(results: List[Dict], total_time: float):
    """Save cracking results to file."""
    with open('Module4/cracking_results.csv', 'w') as f:
        f.write("User,Password,Time_Seconds,Attempts,Workfactor\n")
        for r in results:
            password = r['password'] if r['password'] else 'NOT_FOUND'
            time_val = r['time'] if r['time'] else 0
            f.write(f"{r['user']},{password},{time_val:.2f},{r['attempts']},{r['workfactor']}\n")
        f.write(f"\nTotal_Time,{total_time:.2f}\n")
    
    logger.log(f"Results saved to Module4/cracking_results.csv")


def quick_test():
    """Quick test to verify bcrypt functionality."""
    print("Running quick bcrypt test...\n")
    
    # Verify test vector
    verify_test_vector()
    
    print()
    
    # Test with a known password
    password = "testing"
    salt = bcrypt.gensalt(rounds=4)  # Low rounds for quick test
    hashed = bcrypt.hashpw(password.encode(), salt)
    
    print(f"Custom test:")
    print(f"  Password: {password}")
    print(f"  Salt: {salt}")
    print(f"  Hash: {hashed}")
    
    # Verify
    is_valid = bcrypt.checkpw(password.encode(), hashed)
    print(f"  Verification: {is_valid}")
    
    return is_valid


if __name__ == "__main__":
    import argparse
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        quick_test()
    else:
        # Parse arguments
        background = '--background' in sys.argv
        parallel = 0
        
        if '--parallel' in sys.argv:
            idx = sys.argv.index('--parallel')
            # Check if next arg is a number
            if idx + 1 < len(sys.argv) and sys.argv[idx + 1].isdigit():
                parallel = int(sys.argv[idx + 1])
            else:
                parallel = multiprocessing.cpu_count()
        
        main(background_mode=background, parallel=parallel)
