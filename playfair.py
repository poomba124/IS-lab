def create_matrix(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    
    matrix_chars = ""
    for char in key + alphabet:
        if char not in matrix_chars:
            matrix_chars += char
            
    matrix = []
    for i in range(0, 25, 5):
        row = [matrix_chars[i], matrix_chars[i+1], matrix_chars[i+2], matrix_chars[i+3], matrix_chars[i+4]]
        matrix.append(row)
        
    return matrix

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None, None

def prepare_text(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    
    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        
        if i + 1 == len(text):
            b = 'X'
        else:
            b = text[i+1]
            
        if a == b:
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2
            
    if len(prepared) % 2 != 0:
        prepared += 'X'
        
    return prepared

def playfair_encrypt(plain_text, key):
    matrix = create_matrix(key)
    digraphs = prepare_text(plain_text)
    cipher_text = ""

    for i in range(0, len(digraphs), 2):
        a, b = digraphs[i], digraphs[i+1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            cipher_text += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            cipher_text += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            cipher_text += matrix[r1][c2] + matrix[r2][c1]
            
    return cipher_text

def playfair_decrypt(cipher_text, key):
    matrix = create_matrix(key)
    decrypted_text = ""

    for i in range(0, len(cipher_text), 2):
        a, b = cipher_text[i], cipher_text[i+1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            decrypted_text += matrix[r1][(c1 - 1 + 5) % 5] + matrix[r2][(c2 - 1 + 5) % 5]
        elif c1 == c2:
            decrypted_text += matrix[(r1 - 1 + 5) % 5][c1] + matrix[(r2 - 1 + 5) % 5][c2]
        else:
            decrypted_text += matrix[r1][c2] + matrix[r2][c1]
            
    return decrypted_text

if __name__ == "__main__":
    message = "The key is hidden under the door pad"
    key = "GUIDANCE"

    encrypted_message = playfair_encrypt(message, key)
    print(f"Original Message:  '{message}'")
    print(f"Encrypted Message:  {encrypted_message}")

    decrypted_message = playfair_decrypt(encrypted_message, key)
    print(f"Decrypted Message:  {decrypted_message}")
