import os
import random
import hashlib
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configure logging
logging.basicConfig(filename='security.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class AdaptiveEncryption:
    def __init__(self):
        self.base_key = os.urandom(16)  # Initial 16-byte key
        self.attempts = 0
        self.fake_data = [b"FakeData1", b"FakeData2", b"DecoyMessage"]
        self.users = {"admin": hashlib.sha256("password123".encode()).hexdigest()}  # Simple user authentication
    
    def mutate_key(self):
        """Modify the key slightly upon each attempt."""
        salt = os.urandom(8)
        self.base_key = hashlib.sha256(self.base_key + salt).digest()[:16]
        logging.warning("Key mutation triggered due to failed decryption attempt.")
    
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
            logging.error("Unauthorized decryption attempt detected! Attempt: %d", self.attempts)
            if self.attempts > 3:
                return random.choice(self.fake_data).decode()  # Return fake data
            return "Decryption Failed! Attempt Logged."
    
    def authenticate_user(self, username, password):
        """Simple user authentication check."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if self.users.get(username) == hashed_password:
            logging.info("User %s authenticated successfully.", username)
            return True
        else:
            logging.warning("Failed login attempt for user %s.", username)
            return False

# Demo Usage
encryption_system = AdaptiveEncryption()
secret_message = "This is a secret message."
ciphertext = encryption_system.encrypt(secret_message)

print("Encrypted:", ciphertext.hex())

# Simulating an unauthorized decryption attempt
for _ in range(5):
    print("Decryption Attempt:", encryption_system.decrypt(ciphertext))

# Simulating authentication attempts
print("Authentication (correct):", encryption_system.authenticate_user("admin", "password123"))
print("Authentication (incorrect):", encryption_system.authenticate_user("admin", "wrongpassword"))
