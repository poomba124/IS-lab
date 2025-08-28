import time
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# --- Setup ---
message = b"Performance Testing of Encryption Algorithms"
des_key = get_random_bytes(8)   # 64-bit key for DES
aes_key = get_random_bytes(32)  # 256-bit key for AES-256
iterations = 10000

# --- DES Benchmark ---
cipher_des = DES.new(des_key, DES.MODE_ECB)
padded_message_des = pad(message, DES.block_size)

start = time.perf_counter()
for _ in range(iterations):
    ct = cipher_des.encrypt(padded_message_des)
des_encrypt_time = ((time.perf_counter() - start) / iterations) * 1_000_000 # microseconds

start = time.perf_counter()
for _ in range(iterations):
    pt = cipher_des.decrypt(ct)
des_decrypt_time = ((time.perf_counter() - start) / iterations) * 1_000_000 # microseconds

# --- AES-256 Benchmark ---
cipher_aes = AES.new(aes_key, AES.MODE_ECB)
padded_message_aes = pad(message, AES.block_size)

start = time.perf_counter()
for _ in range(iterations):
    ct = cipher_aes.encrypt(padded_message_aes)
aes_encrypt_time = ((time.perf_counter() - start) / iterations) * 1_000_000 # microseconds

start = time.perf_counter()
for _ in range(iterations):
    pt = cipher_aes.decrypt(ct)
aes_decrypt_time = ((time.perf_counter() - start) / iterations) * 1_000_000 # microseconds

# --- Report ---
print(f"--- Average over {iterations} iterations ---")
print(f"DES Encryption:     {des_encrypt_time:.2f} µs")
print(f"DES Decryption:     {des_decrypt_time:.2f} µs")
print(f"AES-256 Encryption: {aes_encrypt_time:.2f} µs")
print(f"AES-256 Decryption: {aes_decrypt_time:.2f} µs")