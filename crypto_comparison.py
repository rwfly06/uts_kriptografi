import time
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# ============================================================
# SYMMETRIC CRYPTOGRAPHY - AES & Fernet
# ============================================================

def aes_encrypt_decrypt(plaintext: bytes):
    # Generate AES-256 key and IV
    key = os.urandom(32)  # 256-bit key
    iv  = os.urandom(16)  # 128-bit IV

    # Encrypt
    t0 = time.perf_counter()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    encrypt_time = time.perf_counter() - t0

    # Decrypt
    t0 = time.perf_counter()
    dec = cipher.decryptor()
    padded_plain = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(padded_plain) + unpadder.finalize()
    decrypt_time = time.perf_counter() - t0

    return ciphertext, encrypt_time, decrypt_time, decrypted


def fernet_encrypt_decrypt(plaintext: bytes):
    key = Fernet.generate_key()
    f   = Fernet(key)

    t0 = time.perf_counter()
    token = f.encrypt(plaintext)
    encrypt_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    decrypted = f.decrypt(token)
    decrypt_time = time.perf_counter() - t0

    return token, encrypt_time, decrypt_time, decrypted


# ============================================================
# ASYMMETRIC CRYPTOGRAPHY - RSA-2048
# ============================================================

def rsa_encrypt_decrypt(plaintext: bytes):
    # Key generation
    t_keygen = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    keygen_time = time.perf_counter() - t_keygen

    oaep = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    # Encrypt
    t0 = time.perf_counter()
    ciphertext = public_key.encrypt(plaintext, oaep)
    encrypt_time = time.perf_counter() - t0

    # Decrypt
    t0 = time.perf_counter()
    decrypted = private_key.decrypt(ciphertext, oaep)
    decrypt_time = time.perf_counter() - t0

    return ciphertext, keygen_time, encrypt_time, decrypt_time, decrypted


# ============================================================
# MAIN — run tests & print comparison table
# ============================================================

def main():
    plaintext = b"Kriptografi adalah ilmu menyandikan pesan agar aman dari pihak yang tidak berhak."
    print("=" * 65)
    print("   PERBANDINGAN KRIPTOGRAFI SIMETRIS DAN ASIMETRIS")
    print("=" * 65)
    print(f"\nPlaintext  : {plaintext.decode()}")
    print(f"Panjang    : {len(plaintext)} bytes\n")

    # --- AES ---
    aes_ct, aes_enc_t, aes_dec_t, aes_dec = aes_encrypt_decrypt(plaintext)
    print("── AES-256-CBC (Simetris) " + "─" * 39)
    print(f"  Ciphertext (base64) : {base64.b64encode(aes_ct).decode()}")
    print(f"  Ukuran ciphertext   : {len(aes_ct)} bytes")
    print(f"  Waktu enkripsi      : {aes_enc_t*1000:.4f} ms")
    print(f"  Waktu dekripsi      : {aes_dec_t*1000:.4f} ms")
    print(f"  Dekripsi berhasil   : {aes_dec == plaintext}")

    # --- Fernet ---
    fernet_ct, fernet_enc_t, fernet_dec_t, fernet_dec = fernet_encrypt_decrypt(plaintext)
    print("\n── Fernet/AES-128 (Simetris) " + "─" * 36)
    print(f"  Token (bytes)       : {fernet_ct[:60]}...")
    print(f"  Ukuran ciphertext   : {len(fernet_ct)} bytes")
    print(f"  Waktu enkripsi      : {fernet_enc_t*1000:.4f} ms")
    print(f"  Waktu dekripsi      : {fernet_dec_t*1000:.4f} ms")
    print(f"  Dekripsi berhasil   : {fernet_dec == plaintext}")

    # --- RSA ---
    rsa_ct, rsa_kg_t, rsa_enc_t, rsa_dec_t, rsa_dec = rsa_encrypt_decrypt(plaintext)
    print("\n── RSA-2048 (Asimetris) " + "─" * 41)
    print(f"  Ciphertext (base64) : {base64.b64encode(rsa_ct).decode()[:60]}...")
    print(f"  Ukuran ciphertext   : {len(rsa_ct)} bytes")
    print(f"  Waktu key-gen       : {rsa_kg_t*1000:.4f} ms")
    print(f"  Waktu enkripsi      : {rsa_enc_t*1000:.4f} ms")
    print(f"  Waktu dekripsi      : {rsa_dec_t*1000:.4f} ms")
    print(f"  Dekripsi berhasil   : {rsa_dec == plaintext}")

    # ── Tabel Perbandingan ──────────────────────────────────────
    print("\n" + "=" * 65)
    print("   TABEL PERBANDINGAN")
    print("=" * 65)
    header = f"{'Kriteria':<28} {'AES-256':<12} {'Fernet':<12} {'RSA-2048':<12}"
    print(header)
    print("-" * 65)

    rows = [
        ("Jenis Kriptografi",     "Simetris",    "Simetris",    "Asimetris"),
        ("Jumlah Kunci",          "1 (shared)",  "1 (shared)",  "2 (pub/priv)"),
        (f"Ukuran Ciphertext(B)", f"{len(aes_ct)}", f"{len(fernet_ct)}", f"{len(rsa_ct)}"),
        ("Waktu Enkripsi (ms)",
            f"{aes_enc_t*1000:.4f}",
            f"{fernet_enc_t*1000:.4f}",
            f"{rsa_enc_t*1000:.4f}"),
        ("Waktu Dekripsi (ms)",
            f"{aes_dec_t*1000:.4f}",
            f"{fernet_dec_t*1000:.4f}",
            f"{rsa_dec_t*1000:.4f}"),
        ("Ukuran Kunci",          "256-bit",     "128-bit",     "2048-bit"),
        ("Keamanan Dasar",        "Tinggi",      "Tinggi",      "Sangat Tinggi"),
        ("Kecepatan",             "Sangat Cepat","Cepat",       "Lambat"),
        ("Cocok untuk",           "Data besar",  "Data+auth",   "Key exchange"),
        ("Standar",               "NIST/FIPS",   "RFC 7519",    "PKCS#1 OAEP"),
    ]

    for row in rows:
        print(f"{row[0]:<28} {row[1]:<12} {row[2]:<12} {row[3]:<12}")

    print("=" * 65)
    print("\nKesimpulan:")
    print("  • Simetris (AES/Fernet) jauh lebih cepat untuk enkripsi data.")
    print("  • Asimetris (RSA) lebih aman untuk pertukaran kunci rahasia.")
    print("  • Praktik terbaik: RSA untuk bertukar kunci, AES untuk data.")
    print("=" * 65)

if __name__ == "__main__":
    main()
