#!/usr/bin/env python3
# ======================================
# Crypto Utils Library for CTF
# by Alief's toolkit
# ======================================

from Crypto.Cipher import AES
from Crypto.Util.number import (
    bytes_to_long, long_to_bytes,
    inverse, GCD
)
from Crypto.Util.Padding import pad, unpad
import base64, binascii, math

# ================= Number Theory (RSA etc.) ================= #

def egcd(a, b):
    """Extended Euclidean Algorithm"""
    if b == 0:
        return (a, 1, 0)
    else:
        g, y, x = egcd(b, a % b)
        return (g, x, y - (a // b) * x)

def modinv(a, m):
    """Modular inverse"""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

def chinese_remainder(n, a):
    """CRT combine (solve x ≡ a[i] mod n[i])"""
    sum = 0
    prod = math.prod(n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return sum % prod

def is_perfect_cube(n: int):
    """Check if n is a perfect cube (for small e RSA)"""
    root = round(n ** (1/3))
    return root, root**3 == n

# ================= AES / Block Cipher ================= #

def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext)

def aes_ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# ================= Encoding Helpers ================= #

def from_hex(s: str) -> bytes:
    return binascii.unhexlify(s)

def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def from_b64(s: str) -> bytes:
    return base64.b64decode(s)

def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b2l(b: bytes) -> int:
    return bytes_to_long(b)

def l2b(n: int) -> bytes:
    return long_to_bytes(n)

# ================= Quick Demo ================= #
if __name__ == "__main__":
    print("[*] Demo RSA utils:")
    print("modinv(3,11) =", modinv(3,11))

    print("\n[*] Demo AES utils:")
    key = b"YELLOW SUBMARINE"
    pt = b"Attack at dawn!!"
    ct = aes_ecb_encrypt(key, pt)
    print("ECB CT hex:", to_hex(ct))
    print("ECB Dec:", aes_ecb_decrypt(key, ct))
