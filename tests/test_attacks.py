"""Attack-simulation tests, run against the real Flask app over its test client.

Each test plays a specific adversary:

  1. Replay attacker      — captures a valid submission and resubmits it.
  2. Tampering attacker   — modifies stored ciphertext bit-by-bit.
  3. Rogue-CA attacker    — presents a certificate signed by a look-alike CA.
  4. Stale-capture attack — replays an old request from outside the window.

The fixtures build a fully isolated app instance (own SQLite DB, own CA) in a
temporary directory, register a real user through the HTTP layer, and pull
the user's PKCS#12 keystore straight out of the database — deliberately
simulating what a database-breach attacker would actually obtain.
"""

import base64
import json
import sqlite3
import time
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from app import create_app
from crypto import keys as key_utils
from crypto.ca import CertificateAuthority
from crypto.decrypt import hybrid_decrypt, hybrid_encrypt

OWNER_PASSWORD = "owner-passw0rd!"


@pytest.fixture
def app(tmp_path):
    application = create_app(instance_path=str(tmp_path / "instance"))
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def owner(app, client):
    """Register a form owner with a one-field form, then log the client in as
    a separate respondent (owners cannot submit to their own forms).

    Returns a dict with the form UUID (the only identifier exposed in URLs),
    the owner's public key PEM (fetched the same way a respondent's browser
    would), and the owner's private key — recovered from the PKCS#12 keystore
    in the database, proving the keystore round-trips through real storage.
    """
    client.post("/register", data={"username": "owner", "password": OWNER_PASSWORD})
    client.post("/login", data={"username": "owner", "password": OWNER_PASSWORD})
    client.post("/create-form", data={"title": "Exam feedback", "fields": "Comments"})

    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.row_factory = sqlite3.Row
        user = db.execute("SELECT * FROM users WHERE username = 'owner'").fetchone()
        form = db.execute("SELECT * FROM forms WHERE owner_id = ?", (user["id"],)).fetchone()

    private_key, _cert = key_utils.load_pkcs12_keystore(user["keystore"], OWNER_PASSWORD)
    public_key_pem = client.get(f"/public-key/{user['id']}").get_json()["publicKey"]

    # Submissions require a logged-in non-owner, so the client becomes a
    # registered respondent for the rest of the test.
    client.get("/logout")
    client.post("/register", data={"username": "respondent", "password": "resp0ndent-pw!"})
    client.post("/login", data={"username": "respondent", "password": "resp0ndent-pw!"})

    return {
        "user_id": user["id"],
        "form_uuid": form["form_uuid"],
        "public_key_pem": public_key_pem,
        "private_key": private_key,
    }


def make_submission(owner, plaintext=b'{"Comments": "great module"}', **overrides):
    """Build a valid /submit payload the way the browser would, then apply
    attacker-controlled overrides."""
    payload = {
        "formId": owner["form_uuid"],
        **hybrid_encrypt(owner["public_key_pem"], plaintext),
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ 1. replay


def test_replay_attack_same_nonce_rejected(client, owner):
    """An intercepted request resubmitted verbatim must be rejected: the
    nonce was consumed by the first submission."""
    payload = make_submission(owner)

    first = client.post("/submit", json=payload)
    assert first.status_code == 201

    replay = client.post("/submit", json=payload)  # byte-for-byte identical
    assert replay.status_code == 400
    assert "replay" in replay.get_json()["error"].lower()


def test_replay_with_recycled_nonce_only(client, owner):
    """Even a *fresh* encryption reusing an old nonce must be rejected —
    the defence keys on the nonce, not the ciphertext."""
    nonce = str(uuid.uuid4())
    assert client.post("/submit", json=make_submission(owner, nonce=nonce)).status_code == 201

    second = client.post("/submit", json=make_submission(owner, nonce=nonce))
    assert second.status_code == 400


# ------------------------------------------------------------- 2. tampering


def test_tampered_ciphertext_fails_decryption(client, owner):
    """An attacker with database write access flips bits in stored ciphertext.
    AES-GCM's authentication tag must make decryption fail loudly."""
    assert client.post("/submit", json=make_submission(owner)).status_code == 201

    # Attacker tampers with the stored blob directly in the database.
    with sqlite3.connect(client.application.config["DATABASE"]) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM responses ORDER BY id DESC LIMIT 1").fetchone()
        corrupted = bytearray(base64.b64decode(row["encrypted_data"]))
        corrupted[len(corrupted) // 2] ^= 0xFF  # flip 8 bits mid-ciphertext
        db.execute(
            "UPDATE responses SET encrypted_data = ? WHERE id = ?",
            (base64.b64encode(bytes(corrupted)).decode(), row["id"]),
        )

        tampered = db.execute(
            "SELECT * FROM responses WHERE id = ?", (row["id"],)
        ).fetchone()

    # The owner's decryption (browser-equivalent) must raise, never return garbage.
    with pytest.raises(InvalidTag):
        hybrid_decrypt(
            owner["private_key"],
            tampered["encrypted_key"],
            tampered["iv"],
            tampered["encrypted_data"],
        )


def test_tampered_wrapped_key_fails_decryption(client, owner):
    """Corrupting the RSA-wrapped AES key must also fail (OAEP decoding error)."""
    payload = make_submission(owner)
    wrapped = bytearray(base64.b64decode(payload["encryptedKey"]))
    wrapped[10] ^= 0x01
    payload["encryptedKey"] = base64.b64encode(bytes(wrapped)).decode()

    # The server still stores it (it cannot inspect ciphertext)...
    assert client.post("/submit", json=payload).status_code == 201
    # ...but the owner's decryption detects the corruption.
    with pytest.raises(ValueError):
        hybrid_decrypt(
            owner["private_key"], payload["encryptedKey"], payload["iv"], payload["encryptedData"]
        )


# ------------------------------------------------------------ 3. rogue CA


def test_foreign_certificate_rejected(app, tmp_path):
    """A certificate signed by a look-alike rogue CA must fail chain
    validation against the app's root, even with an identical subject name."""
    rogue_ca = CertificateAuthority(str(tmp_path / "rogue-ca"))
    victim_key = key_utils.generate_rsa_keypair()
    rogue_cert = rogue_ca.issue_certificate(victim_key.public_key(), "owner")

    valid, reason = app.config["CA"].verify_certificate(rogue_cert)
    assert not valid
    assert reason  # a human-readable rejection reason is always given


def test_genuine_certificate_verifies_via_route(client, owner):
    """Sanity check the /verify-cert endpoint: a CA-issued cert must pass."""
    verdict = client.get(f"/verify-cert?user_id={owner['user_id']}").get_json()
    assert verdict["valid"] is True
    assert verdict["subject"] == "CN=owner"


# ------------------------------------------------- 4. expired timestamp


def test_expired_timestamp_rejected(client, owner):
    """A captured request replayed 6 minutes later — with a brand-new nonce —
    must be rejected purely on timestamp freshness."""
    six_minutes_ago = int((time.time() - 360) * 1000)
    payload = make_submission(owner, timestamp=six_minutes_ago)

    response = client.post("/submit", json=payload)
    assert response.status_code == 400
    assert "timestamp" in response.get_json()["error"].lower()


def test_future_timestamp_rejected(client, owner):
    """Timestamps far in the future (beyond clock-skew tolerance) are also
    rejected — otherwise an attacker could pre-date a capture to extend its
    replay lifetime."""
    ten_minutes_ahead = int((time.time() + 600) * 1000)
    payload = make_submission(owner, timestamp=ten_minutes_ahead)
    assert client.post("/submit", json=payload).status_code == 400


# --------------------------------------------------- bonus: breach realism


def test_database_contains_no_plaintext(client, owner):
    """A full dump of the responses table must not contain the submitted
    plaintext anywhere — the end-to-end guarantee, stated as a test."""
    secret = b'{"Comments": "the secret answer nobody should read"}'
    assert client.post("/submit", json=make_submission(owner, plaintext=secret)).status_code == 201

    with sqlite3.connect(client.application.config["DATABASE"]) as db:
        dump = "\n".join(db.iterdump())

    assert "secret answer" not in dump
    assert "nobody should read" not in dump
