#!/usr/bin/env python3

# PBKDF2 Hybrid Brute-Force Attacker.

# This script performs a hybrid (dictionary + combinatorial) brute-force attack
# on a ciphertext encrypted using Fernet (AES-128-CBC + HMAC-SHA256) with a 
# PBKDF2HMAC-SHA256 derived key.

import time
import base64
from multiprocessing import Pool
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Target salt and ciphertext
salt = b"\xd2\xffs~\xb4\xf2\xd3\xda\xe3\x16('\xe6\xad\xef\xaf"
cyphertext = b"gAAAAABnE2P-qqJT-HudMbLcykzIx83XqZNEt6UqfyBBzhYKvlF9WSx8FJUvUmatzuY1-io9RHWaj7RVBuAKTWRAVT9GpGC--TZUXk387qeTC2jIJOfUrwSX3eGEb1EVFZBOqALd8EKS1CFWUoF4NpzKsc3eLeCnXihb-w6Boqi835uNzN6mZz4iP-6sSkhNxHP-TbrG-BNgjMIyeRDjSLAZhEAJoUGlz_QuOyyOYHMab9LUrXkHibU="

# Dictionary and combinatorial search space parameters
words = [
    "gatto", "giulia", "martina", "password", "pisa",
    "poesia", "qwerty", "sicurezza", "storia", "tavolo"
]

specials = list("!$%&?^*+@#")
digits = [str(d) for d in range(10)]

ITERATIONS = 100000

PROCESSES = 4        
CHUNKSIZE = 32      
REPORT_EVERY = 10000

# Generate single-uppercase character variants of a given base word.
def make_variants(word):
    variants = [word]
    L = len(word)
    for i in range(L):
        variants.append(word[:i] + word[i].upper() + word[i+1:])
    # List containing the original word and all single-uppercase variations.
    return variants

# Calculate the exact number of password candidates in the search space.
def count_total_candidates(words_list):
    total = 0
    for w in words_list:
        L = len(w)
        variants = L + 1                      
        insert_combos = (L + 1) * (L + 2)
        per_variant = 10 * 10 * insert_combos
        total += variants * per_variant
    return total

TOTAL_CANDIDATES = count_total_candidates(words)

# Lazy generator producing candidate passwords combining dictionary words,
# uppercase variations, one digit, and one special character across all positions.
def candidate_generator():
    for w in words:
        for var in make_variants(w):
            L = len(var)
            # Positional placement for digit (pd) and special character (ps)
            for pd in range(L + 1):
                for ps in range(L + 1):
                    if pd != ps:
                        # Distinct positions: insertion order determined by position index
                        for d in digits:
                            for s in specials:
                                base = list(var)
                                items = sorted([(pd, d), (ps, s)], key=lambda x: x[0], reverse=True)
                                for p, ch in items:
                                    base.insert(p, ch)
                                yield ''.join(base)
                    else:
                        # Coincident positions: evaluate both relative insertion orders
                        for d in digits:
                            for s in specials:
                                # Order 1: digit followed by special character
                                b1 = list(var)
                                b1.insert(pd, d)
                                b1.insert(pd+1, s)
                                yield ''.join(b1)

                                # Order 2: special character followed by digit
                                b2 = list(var)
                                b2.insert(pd, s)
                                b2.insert(pd+1, d)
                                yield ''.join(b2)

# Worker function attempting key derivation and decryption for a single candidate.
def test_password_worker(pw):
    try:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
        key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
        f = Fernet(key)
        pt = f.decrypt(cyphertext)
        return (pw, pt)
    except Exception:
        return None

# Execute the multi-core hybrid attack with real-time statistics and ETA tracking.
def main():
    print("Total candidates (exact):", TOTAL_CANDIDATES)
    print(f"Config: PROCESSES={PROCESSES}, CHUNKSIZE={CHUNKSIZE}, ITERATIONS={ITERATIONS}")
    gen = candidate_generator()
    tries = 0
    start_time = time.time()

    with Pool(processes=PROCESSES) as pool:
        for res in pool.imap_unordered(test_password_worker, gen, chunksize=CHUNKSIZE):
            tries += 1
            if res:
                pw, pt = res
                elapsed = time.time() - start_time
                pct = tries / TOTAL_CANDIDATES * 100
                print(f"\nFOUND! password='{pw}' after {tries} tries in {elapsed:.2f}s ({pct:.4f}% of space)")
                print("plaintext:", pt)
                pool.terminate()
                return
            if tries % REPORT_EVERY == 0:
                elapsed = time.time() - start_time
                rate = tries / elapsed if elapsed > 0 else 0.0
                remaining = TOTAL_CANDIDATES - tries
                eta = remaining / rate if rate > 0 else float('inf')
                pct = tries / TOTAL_CANDIDATES * 100
                print(f"tries={tries} elapsed={elapsed:.1f}s rate~{rate:.2f}/s {pct:.4f}% ETA~{eta/60:.2f} min")

    elapsed = time.time() - start_time
    print(f"Done. Tried {tries} candidates in {elapsed:.2f}s - no password found.")

if __name__ == "__main__":
    main()
