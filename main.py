#!/usr/bin/env python3

import hashlib
import os
import sys

def detect_hash_type(hash_str):
    length = len(hash_str.strip())
    return {
        32: 'MD5',
        40: 'SHA1',
        64: 'SHA256',
        128: 'SHA512'
    }.get(length, 'Unknown')

def load_hashes(file_path):
    if not os.path.isfile(file_path):
        print(f"[!] Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def try_crack_single(hash_value, hash_type, wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
            for word in wordlist:
                word = word.strip()
                if not word:
                    continue
                if hash_type == 'MD5' and hashlib.md5(word.encode()).hexdigest() == hash_value:
                    return word
                elif hash_type == 'SHA1' and hashlib.sha1(word.encode()).hexdigest() == hash_value:
                    return word
                elif hash_type == 'SHA256' and hashlib.sha256(word.encode()).hexdigest() == hash_value:
                    return word
                elif hash_type == 'SHA512' and hashlib.sha512(word.encode()).hexdigest() == hash_value:
                    return word
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
    return None

def crack_hashes(hashes):
    cracked = {}
    print("[*] Starting hash cracking...\n")

    rockyou = "/usr/share/wordlists/rockyou.txt"
    crackstation = os.path.expanduser("~/wordlists/crackstation.txt")

    for h in hashes:
        hash_type = detect_hash_type(h)
        print(f"[+] Hash: {h[:10]}... Detected Type: {hash_type}")
        
        result = try_crack_single(h, hash_type, rockyou)
        if result:
            cracked[h] = result
            print(f"    └─ 🔓 Cracked with rockyou: {result}")
            continue

        print(f"    └─ ❌ Not in rockyou — trying CrackStation...")

        result = try_crack_single(h, hash_type, crackstation)
        if result:
            cracked[h] = result
            print(f"    └─ 💥 Cracked with CrackStation: {result}")
        else:
            cracked[h] = "[✘] Not found"
            print(f"    └─ ☠️  Not cracked.")
    
    return cracked

def save_results(results, output_file='results.txt'):
    with open(output_file, 'w') as f:
        for h, pwd in results.items():
            f.write(f"{h} : {pwd}\n")
    print(f"\n[✔] Results saved to '{output_file}'.")

if __name__ == "__main__":
    print("☠️  SHADOWBREAKER v1.2 – Auto Cracking Engine\n")

    hash_file = input("[?] Enter path to hash file: ").strip()
    hashes = load_hashes(hash_file)
    results = crack_hashes(hashes)
    save_results(results)
