#!/usr/bin/env python3

import hashlib
import itertools
import string
import multiprocessing
import os

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

def brute_force_worker(target_hash, characters, length, result_queue):
    """Kaba kuvvet için bir işçi işlemi."""
    for guess in itertools.product(characters, repeat=length):
        guess = ''.join(guess)
        # Tüm hash algoritmaları için deneme yap
        for method in SUPPORTED_HASHES:
            hashed = hash_password(guess, method)
            if hashed == target_hash:
                result_queue.put((method, guess))
                return  # Şifre bulundu, işçiyi durdur

            # İki hash algoritması kombinasyonu ile deneme
            for method2 in SUPPORTED_HASHES:
                if method != method2:  # Aynı algoritmayı kullanma
                    combined_hash = double_hash(guess, method, method2)
                    if combined_hash == target_hash:
                        result_queue.put((f"{method}({method2})", guess))
                        return  # Şifre bulundu, işçiyi durdur

def rainbow_table(target_hash, rainbow_dict):
    """Rainbow tablosunu kullanarak hash'i kontrol et."""
    for password in rainbow_dict:
        # Tüm hash algoritmaları için deneme yap
        for method in SUPPORTED_HASHES:
            if hash_password(password, method) == target_hash:
                return password
    return None

def load_passwords_from_file(file_path):
    """Dosyadan şifreleri yükler."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} bulunamadı.")
    
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def brute_force(target_hash, max_length=4, rainbow_dict=None, passwords_from_file=None):
    """Kaba kuvvet yöntemi ile şifreyi kırmaya çalışır."""
    # Genişletilmiş karakter seti
    characters = string.ascii_letters + string.digits + string.punctuation + " " + "!@#$%^&*()-_=+[]{}|;:',<.>/?"
    result_queue = multiprocessing.Queue()
    
    # 1. Dosya yolunu deneme
    if passwords_from_file:
        for password in passwords_from_file:
            for method in SUPPORTED_HASHES:
                if hash_password(password, method) == target_hash:
                    result_queue.put((method, password))
                    return

    # 2. Rainbow yöntemi
    if rainbow_dict:
        found_password = rainbow_table(target_hash, rainbow_dict)
        if found_password:
            result_queue.put(("Rainbow", found_password))
            return

    # 3. Kaba kuvvet denemeleri
    processes = []
    for length in range(1, max_length + 1):
        process = multiprocessing.Process(target=brute_force_worker, args=(target_hash, characters, length, result_queue))
        processes.append(process)
        process.start()

    # Tüm işlemler tamamlanana kadar bekle
    found_passwords = {}
    for _ in processes:
        method, guess = result_queue.get()
        found_passwords[method] = guess
        print(f"Şifre ({method}) ile bulundu: {guess}")

    for process in processes:
        process.join()

    return found_passwords

def main():
    print("=== Şifre Kırma Aracı ===")
    target_hash = input("Kırmak istediğiniz hash değerini girin: ")
    
    # Kullanıcıdan maksimum uzunluğu alma
    max_length = int(input("Maksimum şifre uzunluğunu girin (varsayılan 10): ") or 10)
    
    # Dosya yolunu ve rainbow tablosunu alma
    file_path = input("Denenecek şifrelerin bulunduğu dosyanın yolunu girin (boş bırakabilirsiniz): ")
    rainbow_file_path = input("Rainbow tablosunun bulunduğu dosyanın yolunu girin (boş bırakabilirsiniz): ")

    passwords_from_file = load_passwords_from_file(file_path) if file_path else []
    rainbow_dict = load_passwords_from_file(rainbow_file_path) if rainbow_file_path else []

    print("\nKırma işlemi başlatılıyor...")
    results = brute_force(target_hash, max_length=max_length, rainbow_dict=rainbow_dict, passwords_from_file=passwords_from_file)

    if not results:
        print("Şifre bulunamadı.")

if __name__ == "__main__":
    main()
