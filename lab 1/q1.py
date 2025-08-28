def additive_cipher(text, key):
  encrypted=""
  for ch in text:
    if ch.isalpha():
      x = (ord(ch)-65+key)%26
      y = chr(x+65)
      encrypted+=y
    else:
      encrypted+=ch
  return encrypted

def additive_decipher(text, key):
  decrypted=""
  for ch in text:
    if ch.isalpha():
      x = (ord(ch)-65-key)%26
      y = chr(x+65)
      decrypted+=y
    else:
      decrypted+=ch
  return decrypted

def multiplicative_cipher(text, key):
  encrypted=""
  for ch in text:
    if ch.isalpha():
      x = ((ord(ch)-65)*key)%26
      y = chr(x+65)
      encrypted += y
    else:
      encrypted+=ch 
  return encrypted

def mod_inverse(key, mod=26):
  for i in range(1, mod):
    if(key * i) % mod == 1:
      return i
  return None

def multiplicative_decipher(text, key):
  decrypted=""
  inv = mod_inverse(key, 26)
  for ch in text:
    if ch.isalpha():
      x = ((ord(ch)-65)*inv)%26
      y = chr(x+65)
      decrypted += y
    else:
      decrypted+=ch
  return decrypted

def affine_cipher(text, key1, key2):
  encrypted = ""
  for ch in text:
    if ch.isalpha():
      x = (((ord(ch)-65)*key1)+key2)%26
      y = chr(x+65)
      encrypted += y
    else:
      encrypted += ch
  return encrypted

def affine_decipher(text, key1, key2):
  decrypted = ""
  inv = mod_inverse(key1, 26)
  for ch in text:
    if ch.isalpha():
      x = ((((ord(ch)-65)-key2)*inv))%26
      y = chr(x+65)
      decrypted += y
    else:
      decrypted += ch
  return decrypted
  
while(True):
  print("MENU")
  print("1. Additive Cipher (key=20)")
  print("2. Multiplicative Cipher (key=15)")
  print("3. Affine Cipher (key=(15,20))")
  print("4. Exit")

  choice = input("Enter your choice: ")

  if choice=="4":
    print("Exiting..")
    break

  text = input("Input text to be encrypted:").upper()

  if choice=="1":
    encrypt = additive_cipher(text, 20)
    decrypt = additive_decipher(encrypt, 20)
    print("Encrypted: ", encrypt)
    print("Decrypted: ", decrypt)

  elif choice == '2':
    enc = multiplicative_cipher(text, 15)
    dec = multiplicative_decipher(enc, 15)
    print("Encrypted:", enc)
    print("Decrypted:", dec)

  elif choice == '3':
    enc = affine_cipher(text, 15, 20)
    dec = affine_decipher(enc, 15, 20)
    print("Encrypted:", enc)
    print("Decrypted:", dec)
  else:
    print("Invalid choice! Try again.")
    