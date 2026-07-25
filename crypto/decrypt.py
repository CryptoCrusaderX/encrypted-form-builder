"""Hybrid AES-GCM / RSA-OAEP encryption and decryption helpers.

In production use, BOTH encryption and decryption happen in the browser via
the Web Crypto API (see ``static/encrypt.js``) — the server never handles
plaintext. This module reimplements the exact same operations in Python so
that:

  1. the pytest suite can simulate a browser submitting real ciphertext, and
  2. the attack-simulation tests can prove that tampering and key mismatch
     are actually detected by the cryptography, not by application code.

WHY hybrid encryption (AES + RSA) instead of RSA alone?
    RSA-OAEP with a 2048-bit key can encrypt at most ~190 bytes — far too
    small for form answers, and RSA is ~1000x slower than AES. The standard
    solution (used by TLS, PGP, S/MIME) is hybrid: encrypt the bulk data
    with a fast symmetric cipher under a random one-time key, then encrypt
    only that small key with RSA. Each response gets a fresh AES key, so
    compromising one response's key reveals nothing about the others.
"""

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# WHY AES-256: 256-bit keys give a comfortable security margin and match the
# browser's `generateKey({name: "AES-GCM", length: 256})`.
AES_KEY_BYTES = 32
# WHY a 96-bit IV: it is the GCM-recommended nonce size (NIST SP 800-38D) —
# larger IVs are internally hashed down, which weakens uniqueness guarantees.
GCM_IV_BYTES = 12

# WHY OAEP with SHA-256 + MGF1(SHA-256): OAEP is the modern RSA padding,
# provably secure against the padding-oracle attacks that break PKCS#1 v1.5
# encryption (Bleichenbacher, 1998). The parameters here mirror Web Crypto's
# `{name: "RSA-OAEP", hash: "SHA-256"}` exactly — if they differed by even
# one hash choice, browser and server would be incompatible.
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def hybrid_encrypt(public_key_pem, plaintext):
    """Encrypt ``plaintext`` (bytes) for the holder of ``public_key_pem``.

    WHAT: performs the same steps as the browser —
      1. generate a random one-time AES-256 key and 96-bit IV,
      2. AES-GCM-encrypt the plaintext (output includes the 16-byte auth tag),
      3. RSA-OAEP-encrypt ("wrap") the AES key with the recipient's public key,
      4. base64-encode everything for JSON transport.

    Returns a dict with ``encryptedData``, ``encryptedKey`` and ``iv`` —
    the exact field names ``POST /submit`` expects.

    WHY GCM and not CBC: GCM is *authenticated* encryption — it produces a
    tag that decryption verifies. Any bit flipped in the ciphertext makes
    decryption fail loudly instead of yielding silently corrupted plaintext.
    That is our tamper-detection mechanism (see tests/test_attacks.py).
    """
    public_key = load_pem_public_key(public_key_pem.encode())

    aes_key = AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)
    iv = os.urandom(GCM_IV_BYTES)  # os.urandom = CSPRNG; never reuse an IV per key
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, associated_data=None)

    wrapped_key = public_key.encrypt(aes_key, _OAEP_PADDING)

    return {
        "encryptedData": base64.b64encode(ciphertext).decode(),
        "encryptedKey": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
    }


def unwrap_aes_key(private_key, encrypted_key_b64):
    """Recover the one-time AES key by RSA-OAEP-decrypting the wrapped key.

    WHY this is the security boundary: only the form owner's private key can
    perform this step. The server stores the wrapped key but — lacking the
    private key — cannot unwrap it, which is what makes the design
    end-to-end encrypted.

    Raises ``ValueError`` if the wrong private key is used (OAEP decoding
    fails in constant time, by design, to avoid padding oracles).
    """
    return private_key.decrypt(base64.b64decode(encrypted_key_b64), _OAEP_PADDING)


def hybrid_decrypt(private_key, encrypted_key_b64, iv_b64, encrypted_data_b64):
    """Full decryption path: unwrap the AES key, then AES-GCM-decrypt the data.

    WHAT: the Python mirror of the browser's decrypt flow in encrypt.js.

    Raises ``cryptography.exceptions.InvalidTag`` if the ciphertext, IV or
    tag were modified in any way — GCM's authentication guarantee. The tests
    rely on this exception to prove tamper detection works.
    """
    aes_key = unwrap_aes_key(private_key, encrypted_key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(encrypted_data_b64)
    return AESGCM(aes_key).decrypt(iv, ciphertext, associated_data=None)
