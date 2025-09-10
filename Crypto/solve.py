#!/usr/bin/env python3
# ==========================================
# Skeleton Solver for Crypto CTF
# by Alief's toolkit
# ==========================================

from crypto_utils import *
# pastikan crypto_utils.py ada di folder yang sama

# =============== SETUP SOAL =============== #
# EDIT BAGIAN INI SESUAI SOAL
MODE = "RSA"   # opsi: RSA, AES, ENCODING

# RSA params (contoh)
N = 0
e = 3
c = 0

# AES params (contoh)
key = b"YELLOW SUBMARINE"
iv  = b"\x00" * 16
ciphertext = b""

# Encoding (contoh)
enc_b64 = "Q0lVMjAyNXtmbGFnfQ=="

# ========================================== #
def solve_rsa():
    """
    Template RSA solver
    - bisa untuk faktor, common modulus, atau broadcast (CRT)
    """
    print("[*] RSA Solver Mode")

    # contoh: small e + CRT (Hastad)
    # misalnya kita punya banyak c dan n
    cs = []  # isi ciphertexts
    ns = []  # isi modulus
    if cs and ns:
        C = chinese_remainder(ns, cs)
        m_root, ok = is_perfect_cube(C)
        if ok:
            print("[+] Recovered:", l2b(m_root))
        else:
            print("[-] Not a perfect cube, coba cara lain")

    # contoh: langsung decrypt
    # phi = (p-1)*(q-1)
    # d = modinv(e, phi)
    # m = pow(c, d, N)
    # print("[+] Flag:", l2b(m))

def solve_aes():
    """
    Template AES solver
    - support ECB, CBC, CTR
    """
    print("[*] AES Solver Mode")

    # contoh ECB decrypt
    try:
        pt = aes_ecb_decrypt(key, ciphertext)
        print("[+] Plaintext:", pt)
    except Exception as ex:
        print("[-] AES error:", ex)

def solve_encoding():
    """
    Template Encoding solver
    """
    print("[*] Encoding Solver Mode")

    pt = from_b64(enc_b64)
    print("[+] Base64 decoded:", pt)

# ========================================== #
if __name__ == "__main__":
    if MODE == "RSA":
        solve_rsa()
    elif MODE == "AES":
        solve_aes()
    elif MODE == "ENCODING":
        solve_encoding()
    else:
        print("[-] Unknown MODE")
