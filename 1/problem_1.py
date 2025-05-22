# Python version 3.9 or later

import os
import timeit


# This is a helper function that returns the length of the input N in bytes.
#
# The cryptographically secure randomness generator, os.urandom, takes as input an
# integer 'size' and outputs 'size' random bytes. These bytes can be interpretted as an
# integer between 0 and 256**size - 1 (both inclusive).
#
# To sample a random number between 0 and N, we compute 'size' so that 256**size is the
# smallest power of 256 greater than or equal to N.
def num_rand_bytes(N):
    return (N.bit_length() + 7) // 8


# Alice's random number generator
def alice_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Initialize with a sentinel so that at least one iteration of the loop is run.
    val = N + 1

    # Keep re-sampling until we obtain a value less that or equal to N.
    while val > N:
        # Get securely generated random bytes.
        random_bytes = os.urandom(num_bytes)
        # Convert the bytestring returned by os.urandom to an integer.
        val = int.from_bytes(random_bytes, "big")

    return val


# Bob's random number generator
def bob_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Get securely generated random bytes.
    random_bytes = os.urandom(num_bytes)

    # Convert the bytestring returned by os.urandom to an integer and reduce it modulo
    # (N+1) to obtain a value between 0 and N.
    val = int.from_bytes(random_bytes, "big") % (N + 1)

    return val


def modified_alice_rand_gen(N):
    num_bytes = num_rand_bytes(N)
    max_value = 256 ** num_bytes - 1  # Maximum value that can be represented by the bytes

    # Rejection threshold to minimize bias
    threshold = max_value - (max_value % (N + 1))

    while True:
        random_bytes = os.urandom(num_bytes)
        val = int.from_bytes(random_bytes, "big")

        # Only return if within the acceptable threshold
        if val < threshold:
            return val % (N + 1)

if __name__ == '__main__':
    import timeit

    time_taken_a = timeit.timeit("alice_rand_gen(255)", setup="from __main__ import alice_rand_gen")
    print(f"Alice takes Time: {time_taken_a} seconds")
    time_taken_b = timeit.timeit("bob_rand_gen(255)", setup="from __main__ import bob_rand_gen")
    print(f"Bob takes Time: {time_taken_b} seconds")
