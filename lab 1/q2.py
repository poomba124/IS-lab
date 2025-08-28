def vigenere_cipher(text, key):
    encrypted=""
    key= key.upper()
    new_key= (key * (len(text) // len(key) + 1))[:len(text)]
    for i in range(len(text)):
        c = (ord(text[i])-65 + (ord(new_key[i])-65))%26
        encrypted += chr(c+65)
    return encrypted

def vigenere_decipher(text, key):
    decrypted=""
    key=key.upper()
    new_key= (key * (len(text) // len(key) + 1))[:len(text)]
    for i in range(len(text)):
        c = (ord(text[i])-65 - (ord(new_key[i])-65))%26
        decrypted += chr(c+65)
    return decrypted

def autokey_cipher(text, key):
    encrypted= ""
    new_key = [key]
    for ch in text[:-1]:
        value = ord(ch)-65
        new_key.append(value)
    for i in range(len(text)):
        p = (ord(text[i]) - 65 + new_key[i])%26
        encrypted += chr(p+65)
    return encrypted

def autokey_decipher(ciphertext, key):
    decrypted = ""
    new_key = [key]
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - 65  
        p = (c - new_key[i] + 26) % 26   
        decrypted += chr(p + 65)
        new_key.append(p) 
    return decrypted

while True:
    print("\n--- MENU ---")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Exit")
    choice = int(input("Enter choice: "))

    if choice == 1:
        text = input("Enter text (UPPERCASE only): ")
        key = input("Enter key (string): ")
        encrypted = vigenere_cipher(text, key)
        print("Encrypted:", encrypted)
        print("Decrypted:", vigenere_decipher(encrypted, key))
    elif choice == 2:
        text = input("Enter text (UPPERCASE only): ")
        key = int(input("Enter key (number): "))
        encrypted = autokey_cipher(text, key)
        print("Encrypted:", encrypted)
        print("Decrypted:", autokey_decipher(encrypted, key))
    elif choice == 3:
        print("Exiting...")
        break
    else:
        print("Invalid choice")
