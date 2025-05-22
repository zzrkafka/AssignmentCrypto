# solution.py
#
# Python 3.9+ recommended
# Install needed libs with:
#   pip install pycryptodome tinyec dissononce
#

import hashlib

from dissononce.hash.sha512 import SHA512Hash
from tinyec.registry import get_curve
from Crypto.Cipher import AES
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.dh.x25519.x25519 import X25519DH, PrivateKey

############################################################
# 1) Recover the server's ECDSA private key (repeated-nonce)
############################################################
from problem import KHandShakeState, ECDSA


def compute_ecdsa_sk(params):
    """
    Recovers TwoDrive's ECDSA secret key by collecting at least
    two signatures with the same nonce 'k'. Because TwoDrive
    uses only 1 fresh random byte for each signature, a collision
    is very likely with ~256+ signatures. Standard repeated-nonce
    ECDSA formulas then yield the private key.

    Returns an integer in [1..n-1], the server's ECDSA sk.
    """
    curve = get_curve("secp256r1")
    N = curve.field.n

    def hash_to_int(msg_bytes):
        return int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big") % N

    seen_r = {}  # map r -> (e, s)
    max_sigs = 2000

    for _ in range(max_sigs):
        message, (r, s) = params.check_update()  # returns (msg_bytes, (r, s))
        e = hash_to_int(message)

        if r in seen_r:
            e1, s1 = seen_r[r]
            e2, s2 = e, s

            # repeated-nonce formula:
            #   k = (e1 - e2)*(s1 - s2)^(-1) mod N
            numerator_k = (e1 - e2) % N
            denom_k = (s1 - s2) % N
            inv_denom_k = pow(denom_k, -1, N)
            k = (numerator_k * inv_denom_k) % N

            #   sk = (s1*k - e1)*r^(-1) mod N
            numerator_sk = (s1 * k - e1) % N
            inv_r = pow(r, -1, N)
            sk = (numerator_sk * inv_r) % N

            return sk
        else:
            seen_r[r] = (e, s)

    # Should be very unlikely to get here if only 1-byte randomness is used:
    return 0


############################################################
# 2) Modify user storage by forging a valid K-handshake msg
############################################################

def modify_user_storage(params, target_data):

    ecdsa_sk = compute_ecdsa_sk(params)

    sk_bytes = ecdsa_sk.to_bytes(16, 'big')
    server_dh_sk = PrivateKey(sk_bytes + b"0" * 16)
    dh = X25519DH()
    server_static_kp = dh.generate_keypair(server_dh_sk)

    handshake = KHandShakeState(
        SymmetricState(CipherState(ChaChaPolyCipher()), SHA512Hash()),
        X25519DH()
    )
    handshake.initialize(
        initiator=True,
        s=server_static_kp,
        e=server_static_kp,
        rs=params.client_static_pk
    )


    msg_buffer = bytearray()

    # The handshake for the K-pattern is: e, es, ss.
    # We process each token sequentially.

    # Pattern token: e
    # Create an ephemeral key and include it in the message.
    msg_buffer.extend(params.client_static_pk.data)
    handshake.symmetricstate.mix_hash(params.client_static_pk.data)

    # Pattern token: es
    # Compute the key es by performing DH key agreement on e and rs.
    # The resulting key is used to update the chaining key using mix_key.
    # See https://noiseprotocol.org/noise.html#the-symmetricstate-object
    handshake.symmetricstate.mix_key(handshake.dh.dh(handshake.e, handshake.rs))

    # Pattern token: es
    # Same as above but compute the key ss by performing DH key agreement on s and rs.
    handshake.symmetricstate.mix_key(handshake.dh.dh(handshake.s, handshake.rs))

    # Encrypt payload
    # Finalize the message by encrypting and authenticating the transcript and payload.
    msg_buffer.extend(handshake.symmetricstate.encrypt_and_hash(target_data))
    handshake_msg = bytes(msg_buffer)
    params.update_storage(handshake_msg)
