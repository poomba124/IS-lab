import string

cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_pt = "ab"
known_ct = "GL"

alpha = string.ascii_lowercase
m = 26

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    # brute-force search for inverse
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No inverse exists")

def idx(c):
    return alpha.index(c.lower())

def chr_i(i):
    return alpha[i % m]

def affine_decrypt(ct, a, b):
    a_inv = mod_inv(a, m)
    pt = ""
    for ch in ct:
        if ch.isalpha():
            y = idx(ch)
            x = (a_inv * (y - b)) % m
            pt += chr_i(x)
        else:
            pt += ch
    return pt

valid_keys = []
for a in range(1, m):
    if gcd(a, m) != 1:
        continue
    for b in range(m):
        c0 = (a * idx(known_pt[0]) + b) % m
        c1 = (a * idx(known_pt[1]) + b) % m
        if chr_i(c0).upper() == known_ct[0] and chr_i(c1).upper() == known_ct[1]:
            valid_keys.append((a, b))

if not valid_keys:
    print("No valid key found")
else:
    a, b = valid_keys[0]
    plaintext = affine_decrypt(cipher, a, b)
    print(f"Found key: a = {a}, b = {b}")
    print("Decrypted plaintext:", plaintext)