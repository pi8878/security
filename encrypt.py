import os
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AdaptiveEncryption:
    def __init__(self):
        self.base_key = os.urandom(16)  # Initial 16-byte key
        self.attempts = 0
        self.fake_data = [b"FakeData1", b"FakeData2", b"DecoyMessage"]
    
    def mutate_key(self):
        """Modify the key slightly upon each attempt."""
        salt = os.urandom(8)
        self.base_key = hashlib.sha256(self.base_key + salt).digest()[:16]
    
    def encrypt(self, plaintext):
        """Encrypts the given plaintext using AES-128 CBC mode."""
        iv = os.urandom(16)
        cipher = AES.new(self.base_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return iv + ciphertext  # Prepend IV for decryption
    
    def decrypt(self, ciphertext):
        """Decrypts the ciphertext, with anti-hacking measures."""
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        try:
            cipher = AES.new(self.base_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            self.attempts = 0  # Reset failed attempts on success
            return decrypted.decode()
        except (ValueError, KeyError):
            self.attempts += 1
            self.mutate_key()
            if self.attempts > 3:
                return random.choice(self.fake_data).decode()  # Return fake data
            return "Decryption Failed! Attempt Logged."

# Demo Usage
encryption_system = AdaptiveEncryption()
secret_message = "This is a secret message."
ciphertext = encryption_system.encrypt(secret_message)

print("Encrypted:", ciphertext.hex())

# Simulating an unauthorized decryption attempt
for _ in range(5):
    print("Decryption Attempt:", encryption_system.decrypt(ciphertext))
