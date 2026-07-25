"""Unit tests for the crypto package: keys, CA, PKCS#12 and hybrid encryption.

These test the building blocks in isolation; tests/test_attacks.py exercises
the same primitives through the full HTTP stack under adversarial conditions.
"""

import pytest
from cryptography.exceptions import InvalidTag

from crypto import keys as key_utils
from crypto.ca import CertificateAuthority
from crypto.decrypt import hybrid_decrypt, hybrid_encrypt


@pytest.fixture
def ca(tmp_path):
    """A fresh mini CA rooted in a temporary directory."""
    return CertificateAuthority(str(tmp_path / "ca"))


@pytest.fixture
def user_key():
    return key_utils.generate_rsa_keypair()


def test_keypair_is_rsa_2048(user_key):
    """The generated keypair must meet the RSA-2048 minimum-security baseline."""
    assert user_key.key_size == 2048
    assert user_key.public_key().public_numbers().e == 65537


def test_ca_issues_verifiable_certificate(ca, user_key):
    """A certificate issued by the CA must chain back to its root."""
    cert = ca.issue_certificate(user_key.public_key(), "alice")
    valid, reason = ca.verify_certificate(cert)
    assert valid, reason
    assert cert.subject.rfc4514_string() == "CN=alice"
    assert cert.issuer == ca.cert.subject


def test_ca_persists_across_restarts(tmp_path, user_key):
    """Reloading the CA from disk must keep the same root, so certificates
    issued before a server restart still verify after it."""
    ca_dir = str(tmp_path / "ca")
    first = CertificateAuthority(ca_dir)
    cert = first.issue_certificate(user_key.public_key(), "bob")

    reloaded = CertificateAuthority(ca_dir)
    valid, _ = reloaded.verify_certificate(cert)
    assert valid
    assert reloaded.cert.serial_number == first.cert.serial_number


def test_pkcs12_roundtrip(ca, user_key):
    """A PKCS#12 keystore must unlock with the right password and return the
    same private key that went in."""
    cert = ca.issue_certificate(user_key.public_key(), "carol")
    keystore = key_utils.create_pkcs12_keystore(user_key, cert, "s3cret-passw0rd", ca.cert)

    recovered_key, recovered_cert = key_utils.load_pkcs12_keystore(keystore, "s3cret-passw0rd")
    assert recovered_key.private_numbers() == user_key.private_numbers()
    assert recovered_cert == cert


def test_pkcs12_rejects_wrong_password(ca, user_key):
    """The keystore must NOT open with a wrong password — this is what makes
    a stolen database dump useless for recovering private keys."""
    cert = ca.issue_certificate(user_key.public_key(), "dave")
    keystore = key_utils.create_pkcs12_keystore(user_key, cert, "correct-password")

    with pytest.raises(ValueError):
        key_utils.load_pkcs12_keystore(keystore, "wrong-password")


def test_hybrid_encrypt_decrypt_roundtrip(user_key):
    """AES-GCM + RSA-OAEP hybrid encryption must round-trip exactly."""
    public_pem = key_utils.public_key_to_pem(user_key.public_key())
    plaintext = b'{"Full name": "Alice", "Symptoms": "headache, \\u00e9t\\u00e9"}'

    envelope = hybrid_encrypt(public_pem, plaintext)
    recovered = hybrid_decrypt(
        user_key, envelope["encryptedKey"], envelope["iv"], envelope["encryptedData"]
    )
    assert recovered == plaintext


def test_each_encryption_uses_fresh_key_and_iv(user_key):
    """Encrypting the same plaintext twice must yield different ciphertexts —
    proof that the AES key and IV are freshly random per submission."""
    public_pem = key_utils.public_key_to_pem(user_key.public_key())
    a = hybrid_encrypt(public_pem, b"same plaintext")
    b = hybrid_encrypt(public_pem, b"same plaintext")
    assert a["encryptedData"] != b["encryptedData"]
    assert a["encryptedKey"] != b["encryptedKey"]
    assert a["iv"] != b["iv"]


def test_wrong_private_key_cannot_decrypt(user_key):
    """A different RSA private key must fail to unwrap the AES key."""
    public_pem = key_utils.public_key_to_pem(user_key.public_key())
    envelope = hybrid_encrypt(public_pem, b"for the owner's eyes only")

    intruder_key = key_utils.generate_rsa_keypair()
    with pytest.raises(ValueError):
        hybrid_decrypt(
            intruder_key, envelope["encryptedKey"], envelope["iv"], envelope["encryptedData"]
        )


def test_gcm_detects_ciphertext_tampering(user_key):
    """Flipping a single bit of ciphertext must make GCM tag verification fail."""
    import base64

    public_pem = key_utils.public_key_to_pem(user_key.public_key())
    envelope = hybrid_encrypt(public_pem, b"integrity matters")

    tampered = bytearray(base64.b64decode(envelope["encryptedData"]))
    tampered[0] ^= 0x01  # flip one bit in the first ciphertext byte
    envelope["encryptedData"] = base64.b64encode(bytes(tampered)).decode()

    with pytest.raises(InvalidTag):
        hybrid_decrypt(
            user_key, envelope["encryptedKey"], envelope["iv"], envelope["encryptedData"]
        )
