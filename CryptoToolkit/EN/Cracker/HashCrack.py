#!/usr/bin/env python3

import hashlib
import itertools
import string
import multiprocessing
import os

# Supported hash algorithms
SUPPORTED_HASHES = [
    'md5', 'sha1', 'sha256', 'sha512', 
    'blake2b', 'sha3_256', 'sha3_512', 
    'ripemd160'
]

def hash_password(password, method='sha256'):
    """Hashes the given password using a specified hash algorithm."""
    if method == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif method == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif method == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif method == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif method == 'blake2b':
        return hashlib.blake2b(password.encode()).hexdigest()
    elif method == 'sha3_256':
        return hashlib.sha3_256(password.encode()).hexdigest()
    elif method == 'sha3_512':
        return hashlib.sha3_512(password.encode()).hexdigest()
    elif method == 'ripemd160':
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(password.encode())
        return ripemd160.hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm.")

def double_hash(password, first_hash, second_hash):
    """Hashes the password using the first and second hash functions."""
    if first_hash not in SUPPORTED_HASHES:
        raise ValueError("Invalid first hash algorithm.")
    if second_hash not in SUPPORTED_HASHES:
        raise ValueError("Invalid second hash algorithm.")
    
    first_hash_value = hash_password(password, first_hash)
    return hash_password(first_hash_value, second_hash)

def brute_force_worker(target_hash, characters, length, result_queue):
    """Worker process for brute force."""
    for guess in itertools.product(characters, repeat=length):
        guess = ''.join(guess)
        # Try all hash algorithms
        for method in SUPPORTED_HASHES:
            hashed = hash_password(guess, method)
            if hashed == target_hash:
                result_queue.put((method, guess))
                return  # Password found, stop worker

            # Try combinations of two hash algorithms
            for method2 in SUPPORTED_HASHES:
                if method != method2:  # Don't use the same algorithm
                    combined_hash = double_hash(guess, method, method2)
                    if combined_hash == target_hash:
                        result_queue.put((f"{method}({method2})", guess))
                        return  # Password found, stop worker

def rainbow_table(target_hash, rainbow_dict):
    """Check the hash using the rainbow table."""
    for password in rainbow_dict:
        # Check against all supported hash algorithms
        for method in SUPPORTED_HASHES:
            if hash_password(password, method) == target_hash:
                return password
    return None

def load_passwords_from_file(file_path):
    """Load passwords from a file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found.")
    
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def brute_force(target_hash, max_length=4, rainbow_dict=None, passwords_from_file=None):
    """Attempts to crack the password using brute force."""
    # Extended character set
    characters = string.ascii_letters + string.digits + string.punctuation + " " + "!@#$%^&*()-_=+[]{}|;:',<.>/?"
    result_queue = multiprocessing.Queue()
    
    # 1. Try the file path
    if passwords_from_file:
        for password in passwords_from_file:
            for method in SUPPORTED_HASHES:
                if hash_password(password, method) == target_hash:
                    result_queue.put((method, password))
                    return

    # 2. Rainbow method
    if rainbow_dict:
        found_password = rainbow_table(target_hash, rainbow_dict)
        if found_password:
            result_queue.put(("Rainbow", found_password))
            return

    # 3. Brute force attempts
    processes = []
    for length in range(1, max_length + 1):
        process = multiprocessing.Process(target=brute_force_worker, args=(target_hash, characters, length, result_queue))
        processes.append(process)
        process.start()

    # Wait for all processes to finish
    found_passwords = {}
    for _ in processes:
        method, guess = result_queue.get()
        found_passwords[method] = guess
        print(f"Password found with ({method}): {guess}")

    for process in processes:
        process.join()

    return found_passwords

def main():
    print("=== Password Cracking Tool ===")
    target_hash = input("Enter the hash value you want to crack: ")
    
    # Get maximum length from user
    max_length = int(input("Enter the maximum password length (default 10): ") or 10)
    
    # Get file path and rainbow table
    file_path = input("Enter the path to the file with passwords to try (leave blank if none): ")
    rainbow_file_path = input("Enter the path to the rainbow table (leave blank if none): ")

    passwords_from_file = load_passwords_from_file(file_path) if file_path else []
    rainbow_dict = load_passwords_from_file(rainbow_file_path) if rainbow_file_path else []

    print("\nStarting cracking process...")
    results = brute_force(target_hash, max_length=max_length, rainbow_dict=rainbow_dict, passwords_from_file=passwords_from_file)

    if not results:
        print("Password not found.")

if __name__ == "__main__":
    main()
