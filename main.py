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

def crack_hashes(hashes, wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(f"[!] Error: Wordlist '{wordlist_path}' not found.")
        sys.exit(1)

    cracked = {}
    print("[*] Starting hash cracking...\n")
    with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
        words = [line.strip() for line in wordlist]
    
    for h in hashes:
        hash_type = detect_hash_type(h)
        print(f"[+] Hash: {h[:10]}... Detected Type: {hash_type}")
        for word in words:
            if hash_type == 'MD5':
                if hashlib.md5(word.encode()).hexdigest() == h:
                    cracked[h] = word
                    break
            elif hash_type == 'SHA1':
                if hashlib.sha1(word.encode()).hexdigest() == h:
                    cracked[h] = word
                    break
            elif hash_type == 'SHA256':
                if hashlib.sha256(word.encode()).hexdigest() == h:
                    cracked[h] = word
                    break
            elif hash_type == 'SHA512':
                if hashlib.sha512(word.encode()).hexdigest() == h:
                    cracked[h] = word
                    break
            else:
                cracked[h] = "[!] Unknown hash type"
                break
        if h not in cracked:
            cracked[h] = "[✘] Not found"

    return cracked

def save_results(results, output_file='results.txt'):
    with open(output_file, 'w') as f:
        for h, pwd in results.items():
            f.write(f"{h} : {pwd}\n")
    print(f"\n[✔] Results saved to '{output_file}'.")

if __name__ == "__main__":
    print("☠️  SHADOWBREAKER v1.1 – Advanced Hash Cracking Engine\n")

    hash_file = input("[?] Enter path to hash file: ").strip()
    wordlist_path = input("[?] Enter path to wordlist (Press ENTER for rockyou.txt): ").strip()
    
    if wordlist_path == "":
        wordlist_path = "/usr/share/wordlists/rockyou.txt"

    hashes = load_hashes(hash_file)
    results = crack_hashes(hashes, wordlist_path)
    save_results(results)

