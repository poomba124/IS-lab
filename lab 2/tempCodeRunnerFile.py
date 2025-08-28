from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# 1. Setup the message and key
plaintext = b"Classified Text"
key_hex = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
key = bytes.fromhex(key_hex)

# 2. Create the Triple DES cipher object in ECB mode
# The library automatically handles the 24-byte key
cipher = DES3.new(key, DES3.MODE_ECB)

# 3. Encrypt the message
# Pad the plaintext to be a multiple of 8 bytes (the DES block size)
padded_plaintext = pad(plaintext, DES3.block_size)
ciphertext = cipher.encrypt(padded_plaintext)

# 4. Decrypt the message
decrypted_padded_text = cipher.decrypt(ciphertext)
# Unpad the decrypted text to get the original message
decrypted_text = unpad(decrypted_padded_text, DES3.block_size)

# 5. Print results and verify
print("--- Triple DES (3DES) Example ---")
print(f"Original Message:  {plaintext.decode()}")
print(f"Ciphertext (Hex):  {ciphertext.hex().upper()}")
print(f"Decrypted Message: {decrypted_text.decode()}")

if plaintext == decrypted_text:
    print("\n✅ Verification Successful: The decrypted message matches the original.")
else:
    print("\n❌ Verification Failed!")