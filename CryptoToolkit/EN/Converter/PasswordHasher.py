#!/usr/bin/env python3

import hashlib

# Supported hash algorithms
SUPPORTED_HASHES = [
    'md5', 'sha1', 'sha256', 'sha512', 
    'blake2b', 'sha3_256', 'sha3_512', 
    'ripemd160'
]

def hash_password(password, method='sha256'):
    """Hashes the given password with a specified hash algorithm."""
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
    """Hashes the password with the first and second hash functions."""
    if first_hash not in SUPPORTED_HASHES:
        raise ValueError("Invalid first hash algorithm.")
    if second_hash not in SUPPORTED_HASHES:
        raise ValueError("Invalid second hash algorithm.")
    
    first_hash_value = hash_password(password, first_hash)
    return hash_password(first_hash_value, second_hash)

def main():
    print("=== Hashing Tool ===")
    password = input("Enter the password you want to hash: ")
    
    # Single-step hash algorithm selection
    print("Single-step hash algorithms:")
    for i, method in enumerate(SUPPORTED_HASHES):
        print(f"{i + 1}. {method}")

    single_hash_choice = int(input("Select a single-step hash algorithm (1-8): ")) - 1
    single_hash_method = SUPPORTED_HASHES[single_hash_choice]

    hashed_password = hash_password(password, single_hash_method)
    print(f"Single-step hashed password ({single_hash_method}): {hashed_password}")

    # Double-step hash algorithm selection
    print("\nDouble-step hash algorithms:")
    for i, method in enumerate(SUPPORTED_HASHES):
        print(f"{i + 1}. {method}")

    first_hash_choice = int(input("Select the first hash algorithm (1-8): ")) - 1
    second_hash_choice = int(input("Select the second hash algorithm (1-8): ")) - 1

    first_hash_method = SUPPORTED_HASHES[first_hash_choice]
    second_hash_method = SUPPORTED_HASHES[second_hash_choice]

    double_hashed_password = double_hash(password, first_hash_method, second_hash_method)
    print(f"Double-step hashed password ({first_hash_method} -> {second_hash_method}): {double_hashed_password}")

if __name__ == "__main__":
    main()
