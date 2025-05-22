# Python version 3.9 or later

# Complete the functions below and include this file in your submission.
#
# You can verify your solution by running `problem_2.py`. See `problem_2.py` for more
# details.

# ------------------------------------- IMPORTANT --------------------------------------
# Do NOT modify the name or signature of the three functions below. You can, however,
# add any additional functons to this file.
# --------------------------------------------------------------------------------------

# Given a ciphertext enciphered using the Caesar cipher, recover the plaintext.
# In the Caesar cipher, each byte of the plaintext is XORed by the key (which is a
# single byte) to compute the ciphertext.
#
# The input `ciphertext` is a bytestring i.e., it is an instance of `bytes`
# (see https://docs.python.org/3.9/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview).
# The function should return the plaintext, which is also a bytestring.
def break_caesar_cipher(ciphertext):
    # Frequency of common letters in English (simplified for analysis)

    def score_plaintext(plaintext):
        # Step 1: Calculate character frequencies in the plaintext
        from collections import Counter
        frequencies = Counter(plaintext)

        # Step 2: Sort characters by frequency in descending order
        sorted_chars = [char for char, _ in frequencies.most_common()]

        # Step 3: Compare sorted order to the common_chars order
        common_chars = b' etaoinshrdlcumwfgypbvkjxqz'
        score = 0

        # Step 4: Give a higher score for characters that match their expected rank
        for i, char in enumerate(sorted_chars):
            if char in common_chars:
                # The closer the ranks are between sorted_chars and common_chars, the higher the score
                expected_rank = common_chars.index(char)
                score += max(0, len(common_chars) - abs(i - expected_rank))  # Reward closer matches

        return score

    best_score = 0
    best_plaintext = b''

    # Try all possible byte values for the XOR key
    for key in range(256):
        # XOR each byte in the ciphertext with the current key
        plaintext = bytes(byte ^ key for byte in ciphertext)

        # Score the result based on English letter frequency
        current_score = score_plaintext(plaintext)

        # Keep track of the plaintext with the highest score
        if current_score > best_score:
            best_score = current_score
            best_plaintext = plaintext

    return best_plaintext


# Given a ciphertext enciphered using a Vigenere cipher, find the length of the secret
# key using the 'index of coincidence' method.
#
# The input `ciphertext` is a bytestring.
# The function returns the key length, which is an `int`.
def find_vigenere_key_length(ciphertext):
    def index_of_coincidence(data):
        n = len(data)
        if n <= 1:
            return 0.0
        freq = [0] * 256  # frequencies of each possible byte
        for b in data:
            freq[b] += 1
        # IC = sum over all byte values of f*(f-1) / (n*(n-1))
        return sum(f * (f - 1) for f in freq) / (n * (n - 1))

    best_length = 1
    best_ic = 0.0

    # Test all lengths from 1..20
    for length in range(1, 21):
        columns = [[] for _ in range(length)]
        # Split ciphertext into `length` columns
        for i, byte in enumerate(ciphertext):
            columns[i % length].append(byte)

        # Compute the average IC across the `length` columns
        avg_ic = sum(index_of_coincidence(col) for col in columns) / length

        if avg_ic > best_ic:
            best_ic = avg_ic
            best_length = length

    return best_length



# Given a ciphertext enciphered using a Vigenere cipher and the length of the key, 
# recover the plaintext.
#
# The input `ciphertext` is a bytestring.
# The function should return the plaintext, which is also a bytestring.
def break_vigenere_cipher(ciphertext, key_length):

    # A simple function to score English-likeness by counting how many
    # characters are in the usual ASCII printable range or typical whitespace.
    def english_score(data):
        # Step 1: Calculate character frequencies in the plaintext
        from collections import Counter
        frequencies = Counter(data)

        # Step 2: Sort characters by frequency in descending order
        sorted_chars = [char for char, _ in frequencies.most_common()]

        # Step 3: Compare sorted order to the common_chars order
        common_chars = b'etaoinshrdlcumwfgypbvkjxqz'
        score = 0

        # Step 4: Give a higher score for characters that match their expected rank
        for i, char in enumerate(sorted_chars):
            if char in common_chars:
                # The closer the ranks are between sorted_chars and common_chars, the higher the score
                expected_rank = common_chars.index(char)
                score += max(0, len(common_chars) - abs(i - expected_rank))  # Reward closer matches

        return score

    # Recover key bytes for each of the `key_length` columns
    key = bytearray(key_length)
    for col in range(key_length):
        column_bytes = ciphertext[col::key_length]  # every key_length-th byte

        best_score = -1
        best_key_byte = 0
        # Try all possible single-byte XOR keys 0..255
        for k in range(256):
            # XOR column bytes with candidate k
            xored = bytes(c ^ k for c in column_bytes)
            sc = english_score(xored)
            if sc > best_score:
                best_score = sc
                best_key_byte = k

        key[col] = best_key_byte

    # Now decrypt the full ciphertext using the recovered key
    plaintext = bytearray(len(ciphertext))
    for i, c in enumerate(ciphertext):
        plaintext[i] = c ^ key[i % key_length]

    return bytes(plaintext)
