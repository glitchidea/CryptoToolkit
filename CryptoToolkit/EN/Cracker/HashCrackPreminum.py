#!/usr/bin/env python3
# Approved

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

# Cryptography (Other/Unclassified)
other_unclassified_ciphers = [
    "Cipher Identifier",
    "Base 26 Cipher",
    "Base 36 Cipher",
    "Base 37 Cipher",
    "Deranged Alphabet Generator",
    "Letters Positions",
    "McCormick Cipher"
]

# Polygrammic Ciphers
polygrammic_ciphers = [
    "Bifid Cipher",
    "Collon Cipher",
    "Digrafid Cipher",
    "Four Square Cipher",
    "Letters Bars",
    "Morbit Cipher",
    "Multi-tap Phone (SMS)",
    "PlayFair Cipher",
    "Pollux Cipher",
    "Three Squares Cipher",
    "Two-square Cipher"
]

# Substitution Ciphers
substitution_ciphers = {
    "Homophonic Substitution Cipher": [
        "Arnold Cipher",
        "Grandpré Cipher",
        "Homophonic Cipher",
        "Mexican Army Cipher Wheel",
        "Modulo Cipher",
        "Nomenclator Cipher"
    ],
    "Symbol Substitution": [
        "Symbols Cipher List",
        "7-Segment Display",
        "Abyss Language (Genshin Impact)",
        "Acéré Cipher",
        "Al Bhed Language",
        "Alien Language ⏃⌰⟟⟒⋏",
        "Alpha Angle System Branding",
        "Alphabet of Angels and Genii",
        "Alphabetum Kaldeorum",
        "American Sign Language",
        "Amharic Language",
        "Amphibia Alphabet",
        "Ancients Alphabet from Stargate",
        "Arthur and the Invisibles Alphabet",
        "Astronomical Symbol",
        "Atlantean Language",
        "Aurebesh Alphabet",
        "Babylonian Numerals",
        "Ballet Alphabet",
        "Betamaze Cipher",
        "Birds on a Wire Cipher",
        "Braille Alphabet",
        "Celestial Alphabet",
        "Chappe Alphabet",
        "Chappe Code",
        "Chinese Code",
        "Circular Glyphs Alphabet",
        "Cistercian Monk Numerals",
        "Clock Cipher",
        "Copiale Cipher",
        "D'ni Numerals",
        "Dada Urka Cipher",
        "Daedric Alphabet",
        "Daggers' Alphabet",
        "Dancing Men Cipher",
        "Deshret Language (Genshin Impact)",
        "Dorabella Cipher",
        "Dothraki Alphabet",
        "Dotsies Font",
        "Dovahzul Language",
        "Draconic Language",
        "Egyptian Numerals",
        "Elder Futhark ᚠᚢᚦᚨᚱᚲ",
        "Enderwalk Language",
        "Enochian Alphabet",
        "Fez Alphabet",
        "Flag Semaphore",
        "French Sign Language",
        "Friderici Cipher (Windows)",
        "Futurama Alien 2 Alphabet",
        "Futurama Alien Alphabet",
        "Gerudo Language",
        "Gnommish Language",
        "Goblin Tolkien Alphabet",
        "Gold Bug Cipher 3‡0†2?3",
        "Goron Language",
        "Gravity Falls Alchemy Cipher",
        "Gravity Falls Bill Cipher",
        "Gravity Falls Bros' Code",
        "Gravity Falls Color Code",
        "Gravity Falls Journal 3",
        "Gravity Falls Rune Cipher",
        "Gravity Falls The Author",
        "Gravity Falls Theraprism Cipher",
        "Halo Covenant Language",
        "Hexahue",
        "Hieroglyphs (Manuel de Codage)",
        "Hylian Language (A Link Between Worlds)",
        "Hylian Language (Breath of the Wild)",
        "Hylian Language (Skyward Sword)",
        "Hylian Language (The Wind Waker)",
        "Hylian Language (Twilight Princess)",
        "Hymnos Alphabet",
        "ITC Zapf Dingbats",
        "Ideograms Cipher (Lines, Circles, Dots)",
        "Inazuman Language (Genshin Impact)",
        "Inuktitut Language",
        "Iokharic Language",
        "Kaktovik Numerals",
        "Kirby (Forgotten Land) Alphabet",
        "Klingon Language",
        "Knots Notation",
        "Kryptonian Alphabet",
        "Lingua Ignota",
        "Lunar Alphabet (L. Katz)",
        "Malachim Alphabet",
        "Malayalam മലയാളം",
        "Mary Stuart Code",
        "Matoran Language",
        "Mayan Numerals",
        "Mirror Digits",
        "Monklish Alphabet",
        "Mourier Alphabet",
        "Music Sheet Cipher",
        "Music Staff Notation",
        "Navy Signals Code",
        "Nazcaän Alphabet",
        "Nyctography Lewis Carroll",
        "Ogham Alphabet",
        "Option-Key Cipher",
        "Outer Rim Basic Alphabet",
        "Passing the River Alphabet",
        "Pigpen Cipher",
        "RataAlada Cipher (Batman)",
        "Rosicrucian Cipher",
        "Sanskrit संस्कृतम्",
        "Semaphore Trousers Cipher",
        "Sheikah Language",
        "Simlish Language",
        "Standard Galactic Alphabet",
        "Stray Alphabet",
        "Sumeru Language (Genshin Impact)",
        "Symbol Font",
        "Tally Marks",
        "Telugu తెలుగు",
        "Templars Cipher",
        "Tenctonese Alphabet",
        "Teyvat Language (Genshin Impact)",
        "Thai ภาษาไทย",
        "Theban Alphabet",
        "Tic-Tac-Toe Cipher",
        "Tifinagh Alphabet (ⵜⵉⴼⵉⵏⴰⵖ)",
        "Tom Tom Code ///\\/",
        "Unown Pokemon Alphabet",
        "Voynich Cipher",
        "Vulcan Language (Star Trek)",
        "Wakanda Alphabet",
        "Webdings Font",
        "Wingdings 2 Font",
        "Wingdings 3 Font",
        "Wingdings Font",
        "Younger Futhark ᚠᚢᚦᚬᚱᚴ",
        "Zodiac Killer Cipher",
        "Zodiac Sign"
    ]
}

# Classical Ciphers
classical_ciphers = [
    "ADFGVX Cipher",
    "ADFGX Cipher",
    "ALT-Codes",
    "ASCII Control Characters",
    "ASCII Shift Cipher",
    "Affine Cipher",
    "Alphabetic Transcription",
    "Alphabetical Ranks Added",
    "Atbash Cipher",
    "Bacon Cipher",
    "Base100 💯",
    "Bazeries Cipher",
    "Binary Character Shapes",
    "Book Cipher",
    "Caesar Cipher",
    "Cardan Grille",
    "Cipher Disk/Wheel",
    "Consonants/Vowels Rank Cipher",
    "D3 Code",
    "DTMF Code",
    "Dice Numbers ⚀⚁⚂",
    "Fractionated Morse Cipher",
    "GS8 Braille Code",
    "Genshin Impact Languages",
    "Gravity Falls Cipher",
    "Greek Letter Number α=1, β=2, γ=3",
    "Grid Coordinates",
    "Hodor Language",
    "Indienne Code",
    "Javascript Keycodes",
    "K6 Code",
    "K7 Code",
    "Kenny Language (Southpark)",
    "Keyboard Change Cipher",
    "Keyboard Coordinates",
    "Keyboard Shift Cipher",
    "LSPK90 Clockwise",
    "Letter Number Code (A1Z26) A=1, B=2, C=3",
    "Malespin",
    "Mono-alphabetic Substitution",
    "Monome-Dinome Cipher",
    "Morse Code",
    "Multiplicative Cipher",
    "Music Notes",
    "NATO Phonetic Alphabet",
    "Nak Nak (Duckspeak)",
    "Navajo Code",
    "Numeric Keypad Draw",
    "Periodic Table Cipher",
    "Phone Keypad Cipher",
    "Polybius Cipher",
    "Prime Multiplication Cipher",
    "Prime Numbers Cipher",
    "ROT-5 Cipher",
    "ROT-13 Cipher",
    "ROT-47 Cipher",
    "ROT1 Cipher",
    "ROT8000 Cipher",
    "ROT Cipher",
    "Rozier Cipher",
    "Shankar Speech Defect (Q&A)",
    "Shift Cipher",
    "Short Weather WKS Codes",
    "Substitution Cipher",
    "T9 (Text Message)",
    "Tap Code Cipher",
    "Triliteral Cipher",
    "Trithemius Ave Maria",
    "Twin Hex Cipher",
    "Unicode Shift",
    "VIC Cipher",
    "Wabun Code",
    "Wolseley Cipher",
    "Word Desubstitution/Pattern",
    "Word Substitution"
]

# Transposition Ciphers
transposition_ciphers = [
    "ADFGVX Cipher",
    "ADFGX Cipher",
    "AMSCO Cipher"
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
    characters = string.ascii_letters + string.digits + string.punctuation
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

    # Get file path and rainbow table
    file_path = input("Enter the path to the file with passwords to try (leave blank if none): ")
    rainbow_file_path = input("Enter the path to the rainbow table (leave blank if none): ")

    passwords_from_file = load_passwords_from_file(file_path) if file_path else []
    rainbow_dict = load_passwords_from_file(rainbow_file_path) if rainbow_file_path else []

    if not target_hash:
        print("Invalid hash value. Please enter a valid hash.")
        return

    if not passwords_from_file and not rainbow_dict:
        print("No password file or rainbow table provided. Starting brute force attempts.")

    print("\nStarting cracking process...")
    results = brute_force(target_hash, max_length=10, rainbow_dict=rainbow_dict, passwords_from_file=passwords_from_file)

    if not results:
        print("Password not found.")

if __name__ == "__main__":
    main()
