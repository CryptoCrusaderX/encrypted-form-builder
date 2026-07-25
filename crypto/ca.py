"""Mini Certificate Authority (CA) for the Encrypted Form Builder PKI.

WHY a CA at all?
    Public keys on their own are just numbers — nothing binds a key to an
    identity. An attacker performing a man-in-the-middle (MITM) attack could
    substitute their own public key and silently read every "encrypted"
    response. X.509 certificates solve this: the CA signs a statement
    ("this public key belongs to user X"), and anyone holding the CA's root
    certificate can verify that signature. A certificate that does not chain
    to our root is rejected, defeating key-substitution MITM attacks.

This module implements a deliberately small, single-level CA:

    Root CA (self-signed) ──signs──▶ user certificates

The root private key is persisted on disk inside the (git-ignored) instance
directory. In a production deployment it would live in an HSM or KMS; for a
coursework-scale PKI, a file the web server can read is the standard
teaching setup.
"""

import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

# Lifetimes: the root outlives every certificate it signs, so user
# certificates can never be "valid" under an expired root.
ROOT_VALIDITY_DAYS = 3650  # 10 years
USER_VALIDITY_DAYS = 365   # 1 year


class CertificateAuthority:
    """A file-backed mini CA: creates a root on first use, then issues and
    verifies user certificates against that root."""

    def __init__(self, ca_dir):
        """Load the CA from ``ca_dir``, creating a fresh root if none exists.

        WHY load-or-create: the CA identity must be stable across server
        restarts — if the root changed on every boot, previously issued
        certificates would all stop verifying.
        """
        self.ca_dir = ca_dir
        self.key_path = os.path.join(ca_dir, "ca_key.pem")
        self.cert_path = os.path.join(ca_dir, "ca_cert.pem")
        os.makedirs(ca_dir, exist_ok=True)

        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            with open(self.key_path, "rb") as fh:
                self.key = serialization.load_pem_private_key(fh.read(), password=None)
            with open(self.cert_path, "rb") as fh:
                self.cert = x509.load_pem_x509_certificate(fh.read())
        else:
            self.key, self.cert = self._create_root()
            with open(self.key_path, "wb") as fh:
                fh.write(
                    self.key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            os.chmod(self.key_path, 0o600)  # root key readable by the server only
            with open(self.cert_path, "wb") as fh:
                fh.write(self.cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def _create_root():
        """Generate the self-signed root certificate.

        WHAT: an RSA-2048 key plus an X.509 certificate where subject ==
        issuer (self-signed) and BasicConstraints CA=TRUE.

        WHY RSA-2048 + SHA-256: RSA-2048 offers ~112-bit security, the
        accepted minimum for new deployments (NIST SP 800-57), and SHA-256
        is the standard collision-resistant hash for certificate signatures.
        WHY CA=TRUE marked *critical*: verifiers must refuse to treat a leaf
        certificate as a CA, which blocks a user from re-signing certificates
        for other identities.
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Encrypted Form Builder Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ST6051CEM Practical Cryptography"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # self-signed: issuer is itself
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=ROOT_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        return key, cert

    def issue_certificate(self, public_key, common_name):
        """Sign an X.509 certificate binding ``public_key`` to ``common_name``.

        WHAT: builds a leaf certificate (CA=FALSE) with the user's name as
        subject and our root as issuer, signed by the root private key.

        WHY random serial numbers: sequential serials enabled real-world
        collision attacks against CAs (the 2008 MD5 rogue-CA attack);
        x509.random_serial_number() gives 159 bits of entropy.
        WHY CA=FALSE critical: prevents this user certificate from being
        used to sign further certificates (privilege escalation).
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=USER_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def verify_certificate(self, cert):
        """Validate that ``cert`` chains to this CA's root.

        Returns ``(valid: bool, reason: str)``.

        WHAT is checked, in order:
          1. Issuer name matches our root's subject (cheap pre-filter).
          2. The certificate is inside its validity window.
          3. The signature over the TBS ("to-be-signed") bytes verifies
             under the root's public key — the actual cryptographic proof.

        WHY this defeats MITM: an attacker can craft a certificate with any
        subject and issuer *name* they like, but they cannot forge the RSA
        signature without the root private key. A certificate signed by any
        other key — including a look-alike rogue CA — fails step 3.
        """
        if cert.issuer != self.cert.subject:
            return False, "Issuer does not match the Encrypted Form Builder root CA"

        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False, "Certificate is outside its validity period"

        try:
            self.cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),  # X.509 certificate signatures use PKCS#1 v1.5
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False, "Signature was not produced by the root CA key"

        return True, "Certificate chains to the Encrypted Form Builder root CA"

    def root_certificate_pem(self):
        """Return the root certificate as PEM text (the public trust anchor).

        WHY expose it: clients need the root certificate to perform their own
        chain validation; the root *certificate* is public by design — only
        the root *key* is secret.
        """
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()
