def hill_cipher(message, key):
  cleaned_text=""
  message = message.upper()
  for char in message:
    if char.isalpha():
      cleaned_text+=char

  if len(cleaned_text) % 2 != 0:
    cleaned_text += "X"

  k = [key[0][0], key[0][1], key[1][0], key[1][1]]
  cipher_text=""

  for i in range(0, len(cleaned_text), 2):
    p1 = ord(cleaned_text[i]) - 65
    p2 = ord(cleaned_text[i+1]) - 65

    c1 = (p1 * k[0] + p2 * k[1]) % 26
    c2 = (p1 * k[2] + p2 * k[3]) % 26

    cipher_text += chr(c1 + 65)
    cipher_text += chr(c2 + 65)

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

print(f"Original: '{message}'")
print(f"Encrypted: {formatted_output}")