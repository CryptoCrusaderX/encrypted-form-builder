"""RSA key generation and PKCS#12 keystore handling.

WHY PKCS#12?
    Private keys must never sit in the database as raw PEM — a database
    breach would then expose every user's decryption key alongside the
    ciphertext, making the encryption pointless. PKCS#12 wraps the private
    key and its certificate in a single password-encrypted container
    (PBKDF2-derived key, standardised in RFC 7292). The password is the
    user's login password, which the server never stores in plaintext, so
    even the server operator cannot open a user's keystore at rest.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

# WHY 2048/65537: RSA-2048 is the NIST-recommended minimum (~112-bit
# security); e=65537 is the universal choice — small enough for fast
# encryption, large enough to avoid the low-exponent attacks that plagued e=3.
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


def generate_rsa_keypair():
    """Generate a fresh RSA-2048 private key (public key is derived from it).

    WHY RSA at all: the browser must encrypt *to* the form owner without any
    shared secret. RSA-OAEP is the asymmetric half of our hybrid scheme —
    anyone with the public key can wrap an AES key that only the private-key
    holder can unwrap. Web Crypto supports RSA-OAEP natively, so browser and
    server interoperate with zero JS libraries.
    """
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )


def public_key_to_pem(public_key):
    """Serialise a public key to SubjectPublicKeyInfo (SPKI) PEM.

    WHY SPKI: it is the exact format Web Crypto's
    ``crypto.subtle.importKey("spki", ...)`` expects, so the browser can
    import this PEM directly after base64-decoding the body.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def private_key_to_pem(private_key):
    """Serialise a private key to unencrypted PKCS#8 PEM.

    WHY unencrypted here: this format is produced only *transiently*, after
    the PKCS#12 keystore has been unlocked with the owner's password, so the
    browser can import it via ``importKey("pkcs8", ...)`` for in-browser
    decryption. It is sent over the authenticated HTTPS session and is never
    written to disk or database.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def create_pkcs12_keystore(private_key, certificate, password, ca_cert=None):
    """Bundle a private key + certificate into a password-protected PKCS#12 blob.

    WHAT: returns ``bytes`` suitable for storage in a database BLOB column.
    The optional CA certificate is included so the bundle carries its full
    chain.

    WHY password-protect with the user's login password: it means the
    keystore at rest is only as accessible as the user's credentials — a
    stolen database dump yields PBKDF2-encrypted containers, not keys.
    """
    return pkcs12.serialize_key_and_certificates(
        name=b"encrypted-form-builder",
        key=private_key,
        cert=certificate,
        cas=[ca_cert] if ca_cert is not None else None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


def load_pkcs12_keystore(keystore_bytes, password):
    """Unlock a PKCS#12 keystore and return ``(private_key, certificate)``.

    Raises ``ValueError`` on a wrong password — the PKCS#12 MAC check fails —
    which doubles as an integrity check on the stored blob.
    """
    private_key, certificate, _additional = pkcs12.load_key_and_certificates(
        keystore_bytes, password.encode()
    )
    return private_key, certificate


def certificate_to_pem(certificate):
    """Serialise an X.509 certificate to PEM text for storage/transport."""
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def certificate_from_pem(pem_text):
    """Parse a PEM-encoded X.509 certificate back into an object."""
    return x509.load_pem_x509_certificate(pem_text.encode())
