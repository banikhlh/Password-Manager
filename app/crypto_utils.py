import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_master_key(password: str, salt: bytes, iterations: int = 600_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

def derive_entry_key(master_key: bytes, site: str, login: str) -> bytes:
    info = f"{site}:{login}".encode()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)

def encrypt_password(plain_text: str, entry_key: bytes) -> bytes:
    aesgcm = AESGCM(entry_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), None)
    return nonce + ciphertext

def decrypt_password(cipher_text: bytes, entry_key: bytes) -> str:
    nonce = cipher_text[:12]
    encrypted = cipher_text[12:]
    aesgcm = AESGCM(entry_key)
    return aesgcm.decrypt(nonce, encrypted, None).decode()