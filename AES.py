from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def AES_encrypt_decrypt(key, data):
  cipher_encrypt = AES.new(key, AES.MODE_ECB)

  padded_data = pad(data, AES.block_size)
  print("Original data: ", data.decode())
  print("Padded data: ", padded_data.hex())

  ciphertext = cipher_encrypt.encrypt(padded_data)
  print("Ciphertext (hex): ", ciphertext.hex())


  cipher_decrypt = AES.new(key, AES.MODE_ECB)

  decrypted_padded_data = cipher_decrypt.decrypt(ciphertext)
  print("Decrypted data with padding: ", decrypted_padded_data)
  unpadded_decrypted_data = unpad(decrypted_padded_data, AES.block_size)
  print("Decrypted data without padding: ", unpadded_decrypted_data)
  return ciphertext, unpadded_decrypted_data

if __name__ == "__main__":
  AES_key_hex = "0123456789ABCDEF0123456789ABCDEF"
  AES_key = bytes.fromhex(AES_key_hex)

  message = "Sensitive Information".encode('utf-8')
  print("Using key: ", AES_key_hex)
  print("Using key(HEX): ", AES_key.hex())
  ciphertext, deciphertext = AES_encrypt_decrypt(AES_key, message)
  

