def createMatrix(key):
  key = key.upper().replace("J", "I")
  alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
  matrix = []
  used = ""
  for ch in key + alphabet:
    if ch not in used:
      used += ch

  for i in range(0, 25, 5):
    row = [used[i], used[i+1], used[i+2], used[i+3], used[i+4]]
    matrix.append(row)

  return matrix

def find_position(matrix, ch):
  for r in  range(5):
    for c in range(5):
      if matrix[r][c] == ch:
        return r, c
  return None

def playfair_cipher(text, key):
  text = text.upper().replace("J", "I").replace(" ","")
  if len(text) % 2 !=0:
    text += "X"

  matrix = createMatrix(key)
  encrypted = ""

  for i in range(0, len(text), 2):
    a, b = text[i], text[i+1]
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    if r1==r2:
      encrypted += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
    elif c1==c2:
      encrypted += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
    else:
      encrypted += matrix[r1][c2] + matrix[r2][c1]
  
  return encrypted

message = "The key is hidden under the door pad"
key = "GUIDANCE"

cipherText = playfair_cipher(message, key)
print("Ciphertext: ", cipherText)
