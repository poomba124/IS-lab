def mod_inv(a, m):
  for i in range(1, m):
    if(a*i) % m == 1:
      return i
  return None

def inverse_key_matrix(key):
  a, b = key[0]
  c, d = key[1]

  det = a*d - c*b
  det = det % 26

  inv_det = mod_inv(det, 26)

  return [[(d * inv_det) % 26, (-b * inv_det) % 26],
          [(-c * inv_det) % 26, (a * inv_det) % 26]]

def hill_decipher(cipher_text, key):
  inverse_key = inverse_key_matrix(key)
  return hill_cipher(cipher_text, inverse_key)

def hill_cipher(message, key):
  text = ""
  message = message.upper()
  for char in message:
    if char.isalpha():
      text += char
  
  if len(text) %2 != 0:
    text += "X"

  k = [key[0][0], key[0][1], key[1][0], key[1][1]]
  cipher_text = ""

  for i in range(0, len(text), 2):
    p1 = ord(text[i]) - 65
    p2 = ord(text[i+1]) - 65

    c1 = (p1 * k[0] + p2 * k[1])%26
    c2 = (p1 * k[2] + p2 * k[3])%26

    cipher_text += chr(c1+65)
    cipher_text += chr(c2+65)
  
  return cipher_text



message = "We live in an insecure world"
key = [[3, 3],
       [2, 7]]

encrypt = hill_cipher(message, key)
chunks = []
for i in range(0, len(encrypt), 4):
  chunk = encrypt[i:i+4]
  chunks.append(chunk)

formatted_output = " ".join(chunks)
print(f"Original:  '{message}'")
print(f"Encrypted: {formatted_output}")
decrypted = hill_decipher(encrypt, key)
print(f"Decrypted: {decrypted}")