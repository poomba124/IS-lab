def rail_fence(message, key):
  rails = [''] * key
  current_rail = 0
  direction = 1

  for char in message:
    rails[current_rail] += char

    if current_rail == 0:
      direction = 1
    elif current_rail == key - 1:
      direction = -1

    current_rail += direction

  return "".join(rails)


    