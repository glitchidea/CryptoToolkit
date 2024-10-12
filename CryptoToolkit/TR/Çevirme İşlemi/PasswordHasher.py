#!/usr/bin/env python3

import hashlib

# Desteklenen hash algoritmaları
SUPPORTED_HASHES = [
    'md5', 'sha1', 'sha256', 'sha512', 
    'blake2b', 'sha3_256', 'sha3_512', 
    'ripemd160'
]

def hash_password(password, method='sha256'):
    """Verilen şifreyi belirli bir hash algoritması ile hash'ler."""
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
        raise ValueError("Desteklenmeyen hash algoritması.")

def double_hash(password, first_hash, second_hash):
    """İlk ve ikinci hash fonksiyonları ile şifreyi hash'ler."""
    if first_hash not in SUPPORTED_HASHES:
        raise ValueError("Geçersiz ilk hash algoritması.")
    if second_hash not in SUPPORTED_HASHES:
        raise ValueError("Geçersiz ikinci hash algoritması.")
    
    first_hash_value = hash_password(password, first_hash)
    return hash_password(first_hash_value, second_hash)

def main():
    print("=== Şifreleme Aracı ===")
    password = input("Hash'lemek istediğiniz şifreyi girin: ")
    
    # Tek aşamalı hash için algoritma seçimi
    print("Tek aşamalı hash algoritmaları:")
    for i, method in enumerate(SUPPORTED_HASHES):
        print(f"{i + 1}. {method}")

    single_hash_choice = int(input("Tek aşamalı hash algoritmasını seçin (1-8): ")) - 1
    single_hash_method = SUPPORTED_HASHES[single_hash_choice]

    hashed_password = hash_password(password, single_hash_method)
    print(f"Tek aşamalı hashlenmiş şifre ({single_hash_method}): {hashed_password}")

    # Çift aşamalı hash için algoritma seçimi
    print("\nÇift aşamalı hash algoritmaları:")
    for i, method in enumerate(SUPPORTED_HASHES):
        print(f"{i + 1}. {method}")

    first_hash_choice = int(input("İlk hash algoritmasını seçin (1-8): ")) - 1
    second_hash_choice = int(input("İkinci hash algoritmasını seçin (1-8): ")) - 1

    first_hash_method = SUPPORTED_HASHES[first_hash_choice]
    second_hash_method = SUPPORTED_HASHES[second_hash_choice]

    double_hashed_password = double_hash(password, first_hash_method, second_hash_method)
    print(f"Çift aşamalı hashlenmiş şifre ({first_hash_method} -> {second_hash_method}): {double_hashed_password}")

if __name__ == "__main__":
    main()