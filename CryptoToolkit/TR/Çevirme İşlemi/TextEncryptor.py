#!/usr/bin/env python3

class Cryptography:
    def __init__(self):
        self.ciphers = {
            "Base 26": self.base_26,
            "Caesar": self.caesar,
            "Atbash": self.atbash,
            "Vigenere": self.vigenere,
            "RSA": self.rsa,
            # Add more cipher methods here
        }

    def base_26(self, text):
        # Örnek: Basit bir Base 26 şifreleme
        return ''.join(chr(65 + (ord(char) - 65) % 26) for char in text.upper() if char.isalpha())

    def caesar(self, text, shift=3):
        encrypted = []
        for char in text:
            if char.isalpha():
                shift_amount = shift % 26
                if char.islower():
                    encrypted.append(chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a')))
                else:
                    encrypted.append(chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A')))
            else:
                encrypted.append(char)
        return ''.join(encrypted)

    def atbash(self, text):
        return ''.join(chr(155 - ord(char)) if char.isalpha() else char for char in text)

    def vigenere(self, text, key):
        key = key.upper()
        encrypted = []
        for i, char in enumerate(text):
            if char.isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                if char.islower():
                    encrypted.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
                else:
                    encrypted.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                encrypted.append(char)
        return ''.join(encrypted)

    def rsa(self, text):
        # Örnek: Basit RSA şifreleme temsili
        return f"RSA encrypted data for '{text}'"

    def select_cipher(self):
        print("Kullanılabilir şifreleme yöntemleri:")
        for i, cipher in enumerate(self.ciphers.keys()):
            print(f"{i + 1}. {cipher}")
        choice = int(input("Bir şifreleme yöntemi seçin (1-5): ")) - 1
        return list(self.ciphers.keys())[choice]

    def run(self):
        selected_cipher = self.select_cipher()
        text = input("Şifrelenecek metni girin: ")
        
        if selected_cipher == "Caesar":
            shift = int(input("Kaydırma miktarını girin: "))
            result = self.ciphers[selected_cipher](text, shift)
        elif selected_cipher == "Vigenere":
            key = input("Anahtarı girin: ")
            result = self.ciphers[selected_cipher](text, key)
        else:
            result = self.ciphers[selected_cipher](text)

        print(f"Şifrelenmiş metin: {result}")


if __name__ == "__main__":
    crypto = Cryptography()
    crypto.run()