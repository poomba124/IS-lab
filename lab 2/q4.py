from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# 1. Setup the message and a SECURE key
plaintext = b"Classified Text"

# This is a secure 24-byte key where K1, K2, and K3 are all different.
key_hex = "1122334455667788AABBCCDDEEFF00119988776655443322"
key = bytes.fromhex(key_hex)

# 2. Create the Triple DES cipher object in ECB mode
cipher = DES3.new(key, DES3.MODE_ECB)

# ... the rest of your code will now work correctly ...

# 3. Encrypt, Decrypt, and Verify
padded_plaintext = pad(plaintext, DES3.block_size)
ciphertext = cipher.encrypt(padded_plaintext)
decrypted_padded_text = cipher.decrypt(ciphertext)
decrypted_text = unpad(decrypted_padded_text, DES3.block_size)

print(f"Ciphertext (Hex): {ciphertext.hex().upper()}")
print(f"Decrypted Message: {decrypted_text.decode()}")
assert plaintext == decrypted_text
print("\n✅ Verification Successful!")