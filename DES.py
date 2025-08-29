from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

def des_encrypt_decrypt(key, data):
  cipher_encrypt = DES.new(key, DES.MODE_ECB)

  padded_data = pad(data, DES.block_size)

  print("Original data: ", data.decode())
  print("Data after padding: ",padded_data.hex())

  ciphertext = cipher_encrypt.encrypt(padded_data)
  print("Ciphertext (hex): ", ciphertext.hex())
  
  cipher_decrypt = DES.new(key, DES.MODE_ECB)
  decrypted_padded_data = cipher_decrypt.decrypt(ciphertext)
  print("Decrypted data with padding: ", decrypted_padded_data.hex())

  unpaded_decrypted_data = unpad(decrypted_padded_data, DES.block_size)
  print("Decrypted data after unpadding: ", unpaded_decrypted_data)
  
  return ciphertext, unpaded_decrypted_data


if __name__ == "__main__":
    des_key = "A1B2C3d4".encode('utf-8')

    message = "Confidential Data".encode('utf-8')

    print(f"Using key: '{des_key.decode()}'\n")
    ciphertext, decrypted_message = des_encrypt_decrypt(des_key, message)
    
    if decrypted_message and message == decrypted_message:
        print("Decryption successfull")
    else:
        print("Decryption failed")

