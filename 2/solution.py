from Crypto.Util import Padding

AES_BLOCK_SIZE = 16


def solve_padding_oracle(ctx, server):
    iv = ctx[:AES_BLOCK_SIZE]
    cipher_blocks = [ctx[i:i + AES_BLOCK_SIZE] for i in range(AES_BLOCK_SIZE, len(ctx), AES_BLOCK_SIZE)]
    plaintext_blocks = []

    for i in reversed(range(len(cipher_blocks))):
        current_block = cipher_blocks[i]
        intermediate = bytearray(AES_BLOCK_SIZE)

        for j in reversed(range(AES_BLOCK_SIZE)):
            padding_byte = AES_BLOCK_SIZE - j
            modified_prev = bytearray(AES_BLOCK_SIZE)
            for k in range(j + 1, AES_BLOCK_SIZE):
                modified_prev[k] = intermediate[k] ^ padding_byte

            for guess in range(256):
                modified_prev[j] = guess
                if server(bytes(modified_prev) + current_block):
                    intermediate[j] = guess ^ padding_byte
                    break

        prev_block = cipher_blocks[i - 1] if i > 0 else iv
        plaintext_block = bytes([intermediate[k] ^ prev_block[k] for k in range(AES_BLOCK_SIZE)])
        plaintext_blocks.insert(0, plaintext_block)

    combined = b''.join(plaintext_blocks)
    return Padding.unpad(combined, AES_BLOCK_SIZE, 'pkcs7')


def find_cookie_length(device):
    """
    Determines the length (in bytes) of a secret cookie that the device appends to a plaintext message
    before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle.

    Returns:
        int: The length of the secret cookie (in bytes).
    """
    for path_len in range(16):
        # Generate paths of length path_len and path_len+1
        path1 = b'A' * path_len
        path2 = b'A' * (path_len + 1)

        # Obtain ciphertexts
        ct1 = device(path1)
        ct2 = device(path2)

        # Check if the ciphertext length increases by AES_BLOCK_SIZE (16 bytes)
        if len(ct2) - len(ct1) == AES_BLOCK_SIZE:
            c_jump = len(ct2)
            k = (c_jump // AES_BLOCK_SIZE) - 1
            cookie_len = k * AES_BLOCK_SIZE - (path_len + 1 + 8)
            return cookie_len
    # Fallback in case the loop didn't find the jump (theoretically should not happen)
    # This part is a safeguard and can be adjusted based on specific requirements
    for path_len in range(16, 256):  # Extend the search range if necessary
        path1 = b'A' * path_len
        path2 = b'A' * (path_len + 1)
        ct1 = device(path1)
        ct2 = device(path2)
        if len(ct2) - len(ct1) == AES_BLOCK_SIZE:
            c_jump = len(ct2)
            k = (c_jump // AES_BLOCK_SIZE) - 1
            cookie_len = k * AES_BLOCK_SIZE - (path_len + 1 + 8)
            return cookie_len
    return 0  # This line is theoretically unreachable


def find_cookie(device):
    """
    Recovers the secret cookie that the device appends to the plaintext message before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device builds the message as:
                               msg = path + b";cookie=" + cookie
                           and then pads and encrypts msg using AES in CBC mode, while maintaining the CBC chaining
                           state across calls.

    Returns:
        bytes: The secret cookie that was appended to the plaintext.
    """
    cookie_len = find_cookie_length(device)
    recovered_cookie = b''
    for i in range(cookie_len):
        # Calculate prefix length to position the i-th cookie byte at the end of a block
        prefix_len = AES_BLOCK_SIZE - (1 + len(b";cookie=") + i) % AES_BLOCK_SIZE
        prefix = b'A' * prefix_len
        known_part = prefix + b";cookie=" + recovered_cookie
        cur_block = int((i+9) / AES_BLOCK_SIZE)
        # First call to obtain the IV for the next encryption
        ct_ref = device(b'A' * 16 + prefix)
        iv = ct_ref[-AES_BLOCK_SIZE:]
        # Brute-force the i-th byte
        for guess in range(256):
            # Craft path to place the guessed byte at the correct position
            crafted_path = (known_part + bytes([guess]))[-16:]
            # print(len(crafted_path))
            path = bytes([x ^ y ^ z for x, y, z in
                          zip(crafted_path,
                              iv,
                              ct_ref[cur_block * AES_BLOCK_SIZE:(cur_block+1) * AES_BLOCK_SIZE])])
            ct_guess = device(path)

            # Check if the first ciphertext block matches the IV used for this encryption
            if ct_ref[(cur_block + 1) * AES_BLOCK_SIZE:(cur_block + 2) * AES_BLOCK_SIZE] == ct_guess[:AES_BLOCK_SIZE]:
                recovered_cookie += bytes([guess])
                break
            else:
                iv = ct_guess[-AES_BLOCK_SIZE:]

    return recovered_cookie
