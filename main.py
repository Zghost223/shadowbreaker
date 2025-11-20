#!/usr/bin/env python3

import hashlib
import os
import sys
import argparse
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from Cryptodome.Hash import SHA256, PBKDF2, bcrypt
import itertools
import string
import argon2  # For Argon2 support

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HashCracker:
    def __init__(self, wordlists, max_workers=4, config_file=None, learn_mode=False):
        self.wordlists = wordlists
        self.max_workers = max_workers
        self.config = self.load_config(config_file)
        self.learn_mode = learn_mode
        # Hash functions with explanations
        self.hash_functions = {
            'MD5': (lambda pwd: hashlib.md5(pwd.encode()).hexdigest(), 
                    "MD5: Fast but insecure (collisions possible). Used in old systems."),
            'SHA1': (lambda pwd: hashlib.sha1(pwd.encode()).hexdigest(), 
                     "SHA1: Better than MD5 but still vulnerable to collisions."),
            'SHA256': (lambda pwd: hashlib.sha256(pwd.encode()).hexdigest(), 
                       "SHA256: Secure for most uses; part of SHA-2 family."),
            'SHA512': (lambda pwd: hashlib.sha512(pwd.encode()).hexdigest(), 
                       "SHA512: Stronger SHA-2 variant for high-security needs."),
            'BCRYPT': (lambda pwd: bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode(), 
                       "Bcrypt: Slow and salted; resists brute force."),
            'PBKDF2': (lambda pwd: PBKDF2(pwd.encode(), b'salt', 32, count=100000).hex(), 
                       "PBKDF2: Key derivation function; uses iterations for slowness."),
            'NTLM': (lambda pwd: hashlib.new('md4', pwd.encode('utf-16le')).hexdigest(), 
                     "NTLM: Used in Windows; MD4-based, easily cracked."),
            'ARGON2': (lambda pwd: argon2.hash_password_raw(pwd.encode(), salt=b'somesalt', time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=argon2.Type.ID).hex(), 
                       "Argon2: Modern, memory-hard hash; winner of Password Hashing Competition.")
        }

    def load_config(self, config_file):
        if config_file and os.path.isfile(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}

    def detect_hash_type(self, hash_str):
        # Improved detection with regex
        import re
        hash_str = hash_str.strip()
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return 'MD5'
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_str):
            return 'SHA1'
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_str):
            return 'SHA256'
        elif re.match(r'^[a-fA-F0-9]{128}$', hash_str):
            return 'SHA512'
        elif hash_str.startswith('$2b$') or hash_str.startswith('$2a$'):
            return 'BCRYPT'
        elif re.match(r'^[a-fA-F0-9]{32}$', hash_str) and len(hash_str) == 32:  # NTLM is also 32 chars
            # Note: NTLM detection is tricky; assume if not MD5
            return 'NTLM'  # In practice, use context or tools like hashid
        elif hash_str.startswith('$argon2'):  # Argon2 prefix
            return 'ARGON2'
        return 'Unknown'

    def load_hashes(self, file_path):
        if not os.path.isfile(file_path):
            logging.error(f"Hash file '{file_path}' not found.")
            sys.exit(1)
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def try_crack_single(self, hash_value, hash_type, wordlist_path):
        func, desc = self.hash_functions.get(hash_type, (None, "Unknown"))
        if self.learn_mode:
            print(f"Learning: {desc}")
        if not func:
            return None
        try:
            with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
                for word in wordlist:
                    word = word.strip()
                    if not word:
                        continue
                    if func(word) == hash_value:
                        return word
        except FileNotFoundError:
            logging.warning(f"Wordlist not found: {wordlist_path}")
        return None

    def brute_force(self, hash_value, hash_type, max_length=4):
        func, desc = self.hash_functions.get(hash_type, (None, "Unknown"))
        if self.learn_mode:
            print(f"Learning: Brute force tries all combinations. {desc}")
        if not func:
            return None
        chars = string.ascii_letters + string.digits + string.punctuation
        total_attempts = sum(len(chars) ** length for length in range(1, max_length + 1))
        with tqdm(total=total_attempts, desc="Brute Force Progress") as pbar:
            for length in range(1, max_length + 1):
                for attempt in itertools.product(chars, repeat=length):
                    pwd = ''.join(attempt)
                    if func(pwd) == hash_value:
                        return pwd
                    pbar.update(1)
        return None

    def hybrid_attack(self, hash_value, hash_type, wordlist_path, rules=None):
        if not rules:
            rules = [lambda w: w, lambda w: w + '123', lambda w: w.upper()]
        func, desc = self.hash_functions.get(hash_type, (None, "Unknown"))
        if self.learn_mode:
            print(f"Learning: Hybrid combines wordlists with rules. {desc}")
        if not func:
            return None
        try:
            with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
                for word in wordlist:
                    word = word.strip()
                    for rule in rules:
                        pwd = rule(word)
                        if func(pwd) == hash_value:
                            return pwd
        except FileNotFoundError:
            logging.warning(f"Wordlist not found: {wordlist_path}")
        return None

    def crack_hash(self, h, attack_mode='wordlist'):
        hash_type = self.detect_hash_type(h)
        if self.learn_mode:
            print(f"Learning: Detected hash type for {h[:10]}... as {hash_type}.")
        logging.info(f"Cracking hash: {h[:10]}... Type: {hash_type}")
        
        if attack_mode == 'wordlist':
            for wl in self.wordlists:
                result = self.try_crack_single(h, hash_type, wl)
                if result:
                    return result
        elif attack_mode == 'brute':
            return self.brute_force(h, hash_type, self.config.get('max_brute_length', 4))
        elif attack_mode == 'hybrid':
            for wl in self.wordlists:
                result = self.hybrid_attack(h, hash_type, wl)
                if result:
                    return result
        return None

    def crack_hashes(self, hashes, attack_mode='wordlist'):
        cracked = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.crack_hash, h, attack_mode): h for h in hashes}
            for future in tqdm(as_completed(futures), total=len(hashes), desc="Cracking Progress"):
                h = futures[future]
                try:
                    result = future.result()
                    cracked[h] = result if result else "[✘] Not found"
                    status = "Cracked" if result else "Not cracked"
                    logging.info(f"Hash {h[:10]}...: {status}")
                except Exception as e:
                    logging.error(f"Error cracking {h[:10]}...: {e}")
                    cracked[h] = "[✘] Error"
        return cracked

    def save_results(self, results, output_file='results.txt'):
        with open(output_file, 'w') as f:
            for h, pwd in results.items():
                f.write(f"{h} : {pwd}\n")
        logging.info(f"Results saved to '{output_file}'.")

    def generate_test_hashes(self, passwords, output_file='test_hashes.txt'):
        """Generate test hashes for ethical learning."""
        with open(output_file, 'w') as f:
            for pwd in passwords:
                for name, (func, _) in self.hash_functions.items():
                    h = func(pwd)
                    f.write(f"{name}:{h}\n")
        print(f"Test hashes generated in '{output_file}'. Use these to test your cracker safely!")

def main():
    parser = argparse.ArgumentParser(description="SHADOWBREAKER v2.1 – Advanced Hash Cracking Engine (Educational)")
    parser.add_argument('hash_file', nargs='?', help="Path to file containing hashes")
    parser.add_argument('--wordlists', nargs='+', default=["/usr/share/wordlists/rockyou.txt", os.path.expanduser("~/wordlists/crackstation.txt")], help="Paths to wordlists")
    parser.add_argument('--attack', choices=['wordlist', 'brute', 'hybrid'], default='wordlist', help="Attack mode")
    parser.add_argument('--workers', type=int, default=4, help="Number of threads")
    parser.add_argument('--config', help="Path to JSON config file")
    parser.add_argument('--output', default='results.txt', help="Output file")
    parser.add_argument('--learn', action='store_true', help="Enable learning mode with explanations")
    parser.add_argument('--generate-test', nargs='+', help="Generate test hashes from passwords (e.g., --generate-test password123 admin)")
    args = parser.parse_args()

    print("☠️  SHADOWBREAKER v2.1 – Advanced Hash Cracking Engine (Educational)\n")
    print("⚠️  ETHICAL USE ONLY: This tool is for learning cryptography and password security. Confirm you have permission and are using it ethically.\n")
    
    confirm = input("Do you confirm ethical use? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Exiting for ethical reasons.")
        sys.exit(0)

    cracker = HashCracker(args.wordlists, args.workers, args.config, args.learn)
    
    if args.generate_test:
        cracker.generate_test_hashes(args.generate_test)
        sys.exit(0)
    
    if not args.hash_file:
        print("No hash file provided. Use --generate-test to create test data.")
        sys.exit(1)
    
    hashes = cracker.load_hashes(args.hash_file)
    results = cracker.crack_hashes(hashes, args.attack)
    cracker.save_results(results, args.output)

if __name__ == "__main__":
    main()
