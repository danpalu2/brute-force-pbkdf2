# PBKDF2 Hybrid Brute-Force & Encryption Suite

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Library-Cryptography-green.svg)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance Python suite for symmetric encryption, decryption, and multi-process hybrid brute-force password recovery targeting **PBKDF2HMAC-SHA256** derived keys and **Fernet** ciphertexts.

---

## Overview

This repository demonstrates the practical security evaluation of low-entropy passwords against hybrid dictionary and combinatorial brute-force attacks, even when protected by Key Derivation Functions (KDFs) like **PBKDF2HMAC-SHA256** with **100,000 iterations**.

### Key Features
- **Symmetric Cipher Operations**: Native implementation of Fernet (AES-128-CBC + HMAC-SHA256) encryption and decryption routines (`encrypt.py` and `decrypt.py`).
- **Hybrid Search Space Generation**: Custom lazy generator (`candidate_generator()`) combining 10 base dictionary words, single-character uppercase variations (`make_variants()`), and positional insertion of digits and special characters.
- **Multi-Process Parallel Acceleration**: Utilizes Python's `multiprocessing.Pool` configured with **4 dedicated worker processes** (`PROCESSES = 4`) and chunked stream processing (`CHUNKSIZE = 32`, `imap_unordered`) to bypass the GIL and maximize evaluation throughput.
- **Exact Space Calculation & Diagnostics**: Pre-calculates the exact search space via `count_total_candidates()` and provides real-time progress updates, hash execution rates (tries/sec), percentage covered, and ETA every **10,000 attempts** (`REPORT_EVERY = 10000`).

---

## Architecture & Technical Details

1. **Key Derivation**: `PBKDF2HMAC` using `SHA-256`, 32-byte key length, and **100,000 iterations**.
2. **Authenticated Encryption**: `Fernet` specification ensuring confidentiality (AES-128-CBC) and integrity verification (HMAC-SHA256).
3. **Memory-Efficient Generator**: Employs Python lazy generators (`yield`) to yield candidates on demand, keeping RAM usage minimal ($O(1)$ space complexity for generation).
4. **Combinatorial Logic**: Evaluates 10 base dictionary words across all single-uppercase variants, combined with 10 digits (`0-9`) and 10 special symbols (`!$%&?^*+@#`) inserted across all possible positional permutations (handling both distinct positions $pd \neq ps$ and coincident positions $pd = ps$).

---

## Repository Structure

```text
.
├── brute_force.py   # Parallelized hybrid brute-force attack script
├── encrypt.py       # Symmetric encryption script using PBKDF2 + Fernet
├── decrypt.py       # Decryption script with try-except key validation
├── requirements.txt # Project dependencies
└── README.md        # Project documentation
```

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- `cryptography` Python package

### Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/danpalu2/brute-force-pbkdf2.git](https://github.com/danpalu2/brute-force-pbkdf2.git)
   cd brute-force-pbkdf2
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### 1. Run the Hybrid Brute-Force Attack
Executes the parallel attack against the hardcoded target ciphertext and salt:
```bash
python brute_force.py
```

### 2. Encrypt a Custom Message
Generates a random salt, derives a key via PBKDF2HMAC, and encrypts plaintext with Fernet:
```bash
python encrypt.py
```

### 3. Decrypt a Message
Attempts decryption using a specified password and handles decryption failure exceptions:
```bash
python decrypt.py
```

---

## Disclaimer

This repository was developed for educational purposes and academic research as part of a university cryptography laboratory exercise.
