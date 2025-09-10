# ============================================
# crypto_templates.py
# Kumpulan template dasar buat Crypto CTF
# ============================================

from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import AES
import base64, codecs
from sympy import Integer

# -----------------------------
# 1. RSA - Hastad Broadcast Attack (e kecil, banyak ciphertext)
# -----------------------------
def rsa_hastad(cs, ns, e):
    """
    cs = list of ciphertexts
    ns = list of moduli
    e = exponent (contoh: 3)
    """
    assert len(cs) == len(ns)
    N = 1
    for n in ns: 
        N *= n
    result = 0
    for c, n in zip(cs, ns):
        m = N // n
        result += c * m * inverse(m, n)
    C = result % N
    m = Integer(C).root(e)[0]   # akar e
    return long_to_bytes(m)

# -----------------------------
# 2. RSA - Common Modulus Attack (sama n, beda e)
# -----------------------------
def rsa_common_modulus(c1, c2, e1, e2, n):
    """
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    """
    # Extended Euclid
    def egcd(a, b):
        if b == 0:
            return (1, 0)
        else:
            x, y = egcd(b, a % b)
            return (y, x - (a // b) * y)

    s1, s2 = egcd(e1, e2)
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

# -----------------------------
# 3. AES - CBC Mode Decrypt
# -----------------------------
def aes_cbc_decrypt(cipher_b64, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(cipher_b64)
    pt = cipher.decrypt(ct)
    return pt

# -----------------------------
# 4. AES - ECB Mode Decrypt
# -----------------------------
def aes_ecb_decrypt(cipher_b64, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = base64.b64decode(cipher_b64)
    pt = cipher.decrypt(ct)
    return pt

# -----------------------------
# 5. Encoding Helpers
# -----------------------------
def decode_base64(s):
    return base64.b64decode(s)

def decode_hex(s):
    return bytes.fromhex(s)

def decode_rot13(s):
    return codecs.decode(s, "rot_13")

# -----------------------------
# 6. XOR Cipher
# -----------------------------
def xor_bytes(data, key):
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])
