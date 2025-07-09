import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from werkzeug.security import generate_password_hash, check_password_hash

# --- AES File/Note Encryption ---
BLOCK_SIZE = 16

def get_key(password):
    return hashlib.sha256(password.encode()).digest()  # 256-bit AES key

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

def encrypt_data(data, password):
    key = get_key(password)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = iv + cipher.encrypt(pad(data.encode()))
    return encrypted

def decrypt_data(data, password):
    key = get_key(password)
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data[BLOCK_SIZE:]))
    return decrypted.decode()

# --- Password Hashing for Login System (Salting + Hashing) ---
def hash_password(password):
    return generate_password_hash(password)  # salted + strong

def verify_password(hashed, password):
    return check_password_hash(hashed, password)
