def rail_fence_encrypt(plain_text, key):
  if key==1:
    return plain_text
  
  rails = [''] * key
  current_rail = 0
  direction = 1

  for char in plain_text:
    rails[current_rail] += char
    
    if current_rail == 0:
      direction = 1
    elif current_rail == key - 1:
      direction = -1
    
    current_rail += direction
  
  return "".join(rails)

def rail_fence_decrypt(cipher_text, key):
  if key == 1:
      return cipher_text
  
  rail_lengths = [0] * key
  current_rail = 0
  direction = 1

  for _ in cipher_text:
    rail_lengths[current_rail] += 1

    if current_rail == 0:
      direction = 1
    elif current_rail == key - 1:
      direction = -1

    current_rail += direction

  rails = []
  start = 0
  for length in rail_lengths:
    rails.append(cipher_text[start : length + start])
    start += length

  result = []
  current_rail = 0
  direction = 1

  rail_indices = [0] * key

  for _ in cipher_text:
    char = rails[current_rail][rail_indices[current_rail]]
    result.append(char)
    rail_indices[current_rail] += 1

    if current_rail == 0:
      direction = 1
    elif current_rail == key - 1:
      direction = -1
    
    current_rail += direction


  return "".join(result)

if __name__ == "__main__":
  while(True):
    print("\n--- Rail Fence Cipher ---")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Exit")

    choice = input("Enter your choice (1/2/3): ")
    if choice == '1':
        message = input("Enter the message to encrypt: ").strip() 
        rails = int(input("Enter the no of rails: "))
        encrypted_msg = rail_fence_encrypt(message, rails)
        print(f"\nEncrypted Message: {encrypted_msg}")
    
    elif choice == '2':
      message = input("Enter the message to decrypt: ").strip()
      if not message:
          print("\nError: Message cannot be empty.")
          continue
      try:
          rails = int(input("Enter the number of rails: "))
          if rails < 1:
              print("\nError: Number of rails must be at least 1.")
              continue
          decrypted_message = rail_fence_decrypt(message, rails)
          print(f"\nDecrypted Message: {decrypted_message}")
      except ValueError:
          print("\nError: Invalid number of rails. Please enter an integer.")

    elif choice == '3':
      print("Exiting program.")
      break
