import string

def shift_value(cipher_char, plain_char):
    return (ord(cipher_char) - ord(plain_char)) % 26

def caesar_decrypt(ciphertext, k):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            p = (ord(c) - ord('A') - k) % 26
            plaintext += chr(p + ord('A'))
        else:
            plaintext += c
    return plaintext

if __name__ == "__main__":
    plaintext_sample = "YES"
    ciphertext_sample = "CIW"

    k = shift_value(ciphertext_sample[0], plaintext_sample[0])

    print("Derived Caesar shift:", k)

    cave_text = "XVIEWYWI"
    decoded = caesar_decrypt(cave_text, k)

    print("Ciphertext :", cave_text)
    print("Plaintext  :", decoded)