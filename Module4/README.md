# Cryptographic Hash Functions Lab

**CSC-321: Introduction to Computer Security**

## Overview

This project explores cryptographic hash functions through two main tasks:
1. **Task 1:** Exploring Pseudo-Randomness and Collision Resistance with SHA256
2. **Task 2:** Breaking Real Hashes using Bcrypt password cracking

## AI Citation

**Claude** was used to assist with code generation, debugging, and report writing for this assignment.

## Setup

### Install Dependencies

```bash
cd Module4
pip install -r requirements.txt
```

Or install individually:
```bash
pip install bcrypt nltk matplotlib reportlab
```

### Download NLTK Data (first time only)

```python
import nltk
nltk.download('words')
```

## Running the Code

### Task 1: SHA256 Collision Analysis

```bash
python task1_sha256.py
```

This will:
- Demonstrate SHA256 hashing (Task 1a)
- Show the avalanche effect with 1-bit Hamming distance inputs (Task 1b)
- Find collisions for truncated hashes from 8 to 50 bits (Task 1c)
- Generate graphs: `collision_analysis.png`
- Save results: `collision_results.csv`

**Note:** Finding collisions for larger bit sizes (40+) may take several minutes.

### Task 2: Bcrypt Password Cracker

**Quick test (verify setup):**
```bash
python task2_bcrypt_cracker.py --test
```

**Run interactively:**
```bash
python task2_bcrypt_cracker.py
```

**Run in background (recommended for long runs):**
```bash
python task2_bcrypt_cracker.py --background
```

**Run in background and keep running after terminal closes:**
```bash
nohup python task2_bcrypt_cracker.py --background &
```

**Monitor progress while running:**
```bash
# Watch the log file
tail -f Module4/cracking_log_*.txt

# Check cracked passwords so far
cat Module4/cracking_progress.txt
```

This will:
- Parse the shadow file with 15 users
- Load the NLTK word corpus (~135,000 words, 6-10 characters)
- Crack passwords grouped by workfactor
- Save results: `cracking_results.csv`

**Warning:** This can take 17-18+ hours to complete all passwords! 
- Workfactor 8-9: Minutes to an hour
- Workfactor 10-11: Several hours
- Workfactor 12-13: Many hours to a day

### Generate Report

```bash
python generate_report.py
```

This creates `Cryptographic_Hash_Functions_Report.pdf` with:
- All explanations and answers to questions
- Code documentation
- Results tables

## File Structure

```
Module4/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── shadow.txt               # Shadow file with bcrypt hashes
├── task1_sha256.py          # Task 1 implementation
├── task2_bcrypt_cracker.py  # Task 2 implementation
├── generate_report.py       # Report generation script
├── collision_analysis.png   # Generated graphs (after running Task 1)
├── collision_results.csv    # Collision data (after running Task 1)
├── cracking_results.csv     # Password results (after running Task 2)
└── Cryptographic_Hash_Functions_Report.pdf  # Final report
```

## Shadow File Format

Each line follows the format:
```
User:$Algorithm$Workfactor$SaltHash
```

Example:
```
Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq
```
- User: Bilbo
- Algorithm: 2b (bcrypt)
- Workfactor: 8
- Salt: J9FW66ZdPI2nrIMcOxFYI. (22 characters)
- Hash: qx268uZn.ajhymLP/YHaAsfBGP3Fnmq

## Tips for Faster Cracking

1. **Use multiple machines:** Split the dictionary and run on different computers
2. **Early termination:** If you find all passwords in a workfactor group, the script moves on
3. **Workfactor grouping:** The script processes users with the same workfactor together for efficiency

## Questions Answered in Report

1. **Question 1:** Observations about the avalanche effect when hashing inputs with 1-bit difference
2. **Question 2:** Maximum and expected number of hashes for collision, time estimate for 256-bit collision
3. **Question 3:** Pre-image resistance vs collision resistance for 8-bit digest
4. **Question 4:** Brute force time estimates for word1:word2, word1:word2:word3, and word1:word2:number formats