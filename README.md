# Encryption and Cracking Tools Kit

This project offers a toolkit containing various encryption and hash functions along with password cracking techniques. The Python files included in the project are described below:

1. **TextEncryptor.py**: Encrypts texts using different encryption algorithms.
2. **PasswordHasher.py**: Hashes passwords using specified hash algorithms.
3. **HashCrack.py**: Uses brute force and rainbow table techniques to crack specified hash values.
4. **HashCrackerPremium.py**: An advanced version that includes more encryption techniques and hash cracking methods.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [TextEncryptor.py](#textencryptorpypy)
  - [PasswordHasher.py](#passwordhasherpy)
  - [HashCrack.py](#hashcrackpy)
  - [HashCrackerPremium.py](#hashcrackerpremiumpy)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Supported Encryption Methods](#supported-encryption-methods)
- [Developer Notes](#developer-notes)

## Installation

This toolkit is designed to work with Python 3. You need to have Python 3 installed on your system. The `hashlib` library is part of Python's standard library, so no additional installation is required.

1. Download the project and extract it to a directory.
2. Open a terminal or command prompt and navigate to the directory containing the files.

## Usage

### TextEncryptor.py

The text encryption tool supports the following encryption methods:

- **Base 26**
- **Caesar**
- **Atbash**
- **Vigenere**
- **RSA**

#### How to Use:

1. Run the command `python3 TextEncryptor.py` in the terminal.
2. View the available encryption methods.
3. Enter the text you want to encrypt.
4. If you choose Caesar or Vigenere, enter the required shift or key.
5. Receive the encrypted text output.

### PasswordHasher.py

This tool hashes a given password using various hash algorithms. Supported hash algorithms include MD5, SHA1, SHA256, and SHA512.

#### How to Use:

1. Run the command `python3 PasswordHasher.py` in the terminal.
2. Enter the password you want to hash.
3. Choose a single-stage hash algorithm.
4. For double-stage hashing, select two hash algorithms.
5. Receive the hashed password output.

### HashCrack.py

This tool cracks given hash values using brute force and rainbow table techniques. Users can input a hash value to crack and a file containing potential passwords.

#### How to Use:

1. Run the command `python3 HashCrack.py` in the terminal.
2. Enter the hash value you wish to crack.
3. Specify a file path containing passwords to try (optional).
4. Specify a rainbow table (optional).
5. Receive the cracking results.

### HashCrackerPremium.py

This advanced version includes more encryption and hash cracking techniques. Its usage is similar to that of `HashCrack.py`.

#### How to Use:

1. Run the command `python3 HashCrackerPremium.py` in the terminal.
2. Enter the hash value you want to crack.
3. Specify file paths for passwords and a rainbow table (optional).
4. Receive the cracking results.

## Supported Hash Algorithms

The following hash algorithms are supported:

- MD5
- SHA1
- SHA256
- SHA512
- BLAKE2b
- SHA3-256
- SHA3-512
- RIPEMD-160

## Supported Encryption Methods

### Supported Methods in TextEncryptor.py:

- Base 26
- Caesar Cipher
- Atbash Cipher
- Vigenere Cipher
- RSA

### Additional Features in HashCrackerPremium.py:

- Brute force methods and two-stage hash attempts.
- Quick hash resolution using rainbow tables.

## Developer Notes

- The code structure is optimized for readability and modularity.
- You can update relevant functions to add additional hash algorithms or encryption methods.
- The project can be shared as open source for feedback and contributions.

This toolkit provides a robust starting point for basic encryption and hashing applications. Please feel free to reach out for any issues or development suggestions!
