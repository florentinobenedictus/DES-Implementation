import sys
import socket
import logging
import threading
logging.basicConfig(level = logging.INFO)
SERVER_IP = "1.1.1.1"
SERVER_PORT = 8889


encryption_key_hex = "8b52aec7d4b5229f"
decryption_key_hex = "8b52aec7d4b5229f"

# DES code
## Define macros
initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

final_permutation = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

expansion_p_box = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

straight_p_box = [16, 7, 20, 21, 29, 12, 28, 17,
              1, 15, 23, 26, 5, 18, 31, 10,
              2, 8, 24, 14, 32, 27, 3, 9,
              19, 13, 30, 6, 22, 11, 4, 25]

permuted_choice_1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

permuted_choice_2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

shift_amount = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

## Functions
def generate_round_keys(key):
    round_keys = []

    key_permuted = [key[pc - 1] for pc in permuted_choice_1]

    left_half = key_permuted[:28]
    right_half = key_permuted[28:]

    for i in range(16):
        left_half = left_half[shift_amount[i]:] + left_half[:shift_amount[i]]
        right_half = right_half[shift_amount[i]:] + right_half[:shift_amount[i]]

        combined_key = left_half + right_half
        round_key = [combined_key[pc2 - 1] for pc2 in permuted_choice_2]

        round_keys.append("".join(round_key))

    return round_keys

def initial_permute(data):
    res = ""
    for i in range(64):
        res += data[initial_permutation[i] - 1]
    return res

def expansion_permutation(data):
    res = ""
    for i in range(48):
        res += data[expansion_p_box[i] - 1]
    return res

def s_box_substitution(data):
    res = ""

    for i in range(8):
        block = data[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = s_box[i][row][col]
        res += format(val, '04b')
    return res

def straight_permutation(data):
    res = ""
    for i in range(32):
        res += data[straight_p_box[i] - 1]
    return res

def des_round(data, key):
    expanded_data = expansion_permutation(data)
    xor_result = "".join([str(int(b1) ^ int(b2)) for b1, b2 in zip(expanded_data, key)])
    s_box_result = s_box_substitution(xor_result)
    round_output = straight_permutation(s_box_result)
    return round_output

def final_permute(data):
    res = ""
    for i in range(64):
        res += data[final_permutation[i] - 1]
    return res

def des_encrypt(data, round_keys):
    data = initial_permute(data)
    left_half = data[:32]
    right_half = data[32:]

    for i in range(16):
        new_left_half = right_half
        round_output = des_round(right_half, round_keys[i])
        new_right_half = "".join([str(int(b1) ^ int(b2)) for b1, b2 in zip(left_half, round_output)])
        left_half, right_half = new_left_half, new_right_half
    
    left_half, right_half = right_half, left_half
    combined_data = left_half + right_half

    ciphertext = final_permute(combined_data)
    return ciphertext

def des_decrypt(data, round_keys):
    data = initial_permute(data)

    left_half = data[:32]
    right_half = data[32:]

    for i in range(15, -1, -1):
        new_left_half = right_half
        round_output = des_round(right_half, round_keys[i])
        new_right_half = "".join([str(int(b1) ^ int(b2)) for b1, b2 in zip(left_half, round_output)])
        left_half, right_half = new_left_half, new_right_half

    left_half, right_half = right_half, left_half
    combined_data = left_half + right_half
    ciphertext = final_permute(combined_data)
    return ciphertext

def des_algorithm(key_hex = "e3b98d45a5b38a7f", plaintext_hex = "1f05d3c2872a59b6", ciphertext_hex = "f48e3583f49c76f6"):
    key_binary = bin(int(key_hex, 16))[2:].zfill(64)
    plaintext_binary = bin(int(plaintext_hex, 16))[2:].zfill(64)

    round_keys = generate_round_keys(key_binary)
    encrypted_ciphertext_binary = des_encrypt(plaintext_binary, round_keys)

    ciphertext_binary = bin(int(ciphertext_hex, 16))[2:].zfill(64)
    decrypted_plaintext_binary = des_decrypt(ciphertext_binary, round_keys)

    encrypted_ciphertext = hex(int(encrypted_ciphertext_binary, 2))[2:].zfill(16)
    decrypted_plaintext = hex(int(decrypted_plaintext_binary, 2))[2:].zfill(16)

    return plaintext_hex, encrypted_ciphertext, decrypted_plaintext


def to_des(message):
  plaintext = message or "test socket encrypt des"
  plaintext += '\x00' * (((64 - (len(plaintext) * 8) % 64) + 7) // 8)
  plaintext_hex = plaintext.encode().hex()

  block_size = 16
  plaintext_blocks = [plaintext_hex[i:i + block_size] for i in range(0, len(plaintext_hex), block_size)]

  resulting_ciphertext = ""
  for i in range(len(plaintext_blocks)):
      # print(f"64-bit block {i + 1} - Plaintext: {plaintext_blocks[i]}")
      plaintext_hex, encrypted_ciphertext, decrypted_plaintext = des_algorithm(key_hex = encryption_key_hex, plaintext_hex = plaintext_blocks[i])
      resulting_ciphertext += encrypted_ciphertext
  print("Encrypted blocks:", resulting_ciphertext)
  return resulting_ciphertext

def from_des(message):
    ciphertext_hex = message or "92fa274c335b9f3de5d8da828a9156416592d3b186c98bb3"

    block_size = 16
    ciphertext_blocks = [ciphertext_hex[i:i + block_size] for i in range(0, len(ciphertext_hex), block_size)]

    resulting_plaintext = ""
    for i in range(len(ciphertext_blocks)):
        # print(f"64-bit block {i + 1} - Ciphertext: {ciphertext_blocks[i]}")
        plaintext_hex, encrypted_ciphertext, decrypted_plaintext = des_algorithm(key_hex = decryption_key_hex, ciphertext_hex = ciphertext_blocks[i])
        resulting_plaintext += decrypted_plaintext
    print("Decrypted blocks:", bytes.fromhex(resulting_plaintext).decode())
    return bytes.fromhex(resulting_plaintext).decode()

# Client socket code
def receive_messages(sock):
    while True:
        recv_data = sock.recv(4096)
        if not recv_data:
            raise RuntimeError("connection closed by the server")
        data = eval(recv_data.decode())
        logging.info(f"[SERVER] {data['sender_ip']}:{data['sender_port']} --- {from_des(data['message'])}")

def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (SERVER_IP, SERVER_PORT)
    logging.info(f"opening socket {server_address}")

    try:
        sock.connect(server_address)
        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        receive_thread.start()

        while True:
            message = input()
            logging.info(f"[CLIENT] {message}")
            sock.sendall(to_des(message).encode())
    except Exception as e:
        logging.warning(f"error: {str(e)}")
    finally:
        logging.info("closing socket...")
        sock.close()

if __name__ == "__main__":
    start_client()
