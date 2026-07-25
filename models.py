"""SQLite persistence layer (raw sqlite3, no ORM).

Security-relevant storage decisions:

- ``forms.form_uuid``      : UUID4 used in every user-facing URL, so form and
                             response pages cannot be enumerated by guessing
                             sequential integers (IDOR defence).
- ``users.keystore``       : PKCS#12 blob — the private key is ONLY stored
                             password-encrypted, never as raw PEM.
- ``responses.*``          : base64 ciphertext, wrapped AES key and IV only.
                             There is no plaintext column anywhere; a full
                             database dump yields nothing readable.
- ``nonces.nonce``         : PRIMARY KEY, so replayed submissions violate a
                             uniqueness constraint at the database level —
                             the check is atomic even under concurrency.

All queries use ``?`` parameter placeholders (never string formatting),
which makes SQL injection structurally impossible.
"""

import sqlite3
import uuid

from flask import g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    keystore      BLOB    NOT NULL,   -- PKCS#12, encrypted with the user's password
    certificate   TEXT    NOT NULL,   -- X.509 PEM, signed by the mini CA
    public_key    TEXT    NOT NULL,   -- SPKI PEM, served to respondents
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS forms (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    form_uuid   TEXT    NOT NULL UNIQUE,  -- UUID4, the only id exposed in URLs
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    fields      TEXT    NOT NULL,     -- JSON array of field labels
    is_active   INTEGER NOT NULL DEFAULT 1,  -- 0 once the owner retires the form
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS responses (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id        INTEGER NOT NULL REFERENCES forms(id),
    encrypted_data TEXT    NOT NULL,  -- base64 AES-GCM ciphertext (+ auth tag)
    encrypted_key  TEXT    NOT NULL,  -- base64 RSA-OAEP-wrapped AES key
    iv             TEXT    NOT NULL,  -- base64 96-bit GCM IV
    nonce          TEXT    NOT NULL,  -- UUID4, anti-replay
    timestamp      INTEGER NOT NULL,  -- client Unix time in milliseconds
    submitted_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce   TEXT PRIMARY KEY,          -- uniqueness enforced by the DB itself
    seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(path):
    """Create the schema if it does not exist yet, and migrate databases
    created before the ``form_uuid`` / ``is_active`` columns existed."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)

        # Migration for pre-UUID databases: CREATE TABLE IF NOT EXISTS does not
        # touch existing tables, so add the new columns and backfill UUIDs.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(forms)")}
        if "form_uuid" not in columns:
            conn.execute("ALTER TABLE forms ADD COLUMN form_uuid TEXT")
            for (form_id,) in conn.execute(
                "SELECT id FROM forms WHERE form_uuid IS NULL"
            ).fetchall():
                conn.execute(
                    "UPDATE forms SET form_uuid = ? WHERE id = ?",
                    (str(uuid.uuid4()), form_id),
                )
        if "is_active" not in columns:
            conn.execute("ALTER TABLE forms ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_forms_uuid ON forms(form_uuid)")

        conn.commit()
    finally:
        conn.close()


def get_db(path):
    """Return the per-request connection, opening one if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    """Close the per-request connection (registered as a teardown handler)."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------- users

def create_user(db, username, password_hash, keystore, certificate_pem, public_key_pem):
    """Insert a new user; returns the new user id or None if the name is taken."""
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, keystore, certificate, public_key)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, keystore, certificate_pem, public_key_pem),
        )
        db.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# ---------------------------------------------------------------- forms

def create_form(db, form_uuid, owner_id, title, description, fields_json):
    cur = db.execute(
        "INSERT INTO forms (form_uuid, owner_id, title, description, fields)"
        " VALUES (?, ?, ?, ?, ?)",
        (form_uuid, owner_id, title, description, fields_json),
    )
    db.commit()
    return cur.lastrowid


def get_form_by_uuid(db, form_uuid):
    return db.execute(
        "SELECT * FROM forms WHERE form_uuid = ?", (form_uuid,)
    ).fetchone()


def get_forms_by_owner(db, owner_id):
    return db.execute(
        "SELECT f.*, (SELECT COUNT(*) FROM responses r WHERE r.form_id = f.id) AS response_count"
        " FROM forms f WHERE f.owner_id = ? ORDER BY f.id DESC",
        (owner_id,),
    ).fetchall()


def set_form_active(db, form_id, active):
    db.execute(
        "UPDATE forms SET is_active = ? WHERE id = ?", (1 if active else 0, form_id)
    )
    db.commit()


def delete_form(db, form_id):
    """Delete a form and every response submitted to it."""
    db.execute("DELETE FROM responses WHERE form_id = ?", (form_id,))
    db.execute("DELETE FROM forms WHERE id = ?", (form_id,))
    db.commit()


# ------------------------------------------------------------ responses

def store_response(db, form_id, encrypted_data, encrypted_key, iv, nonce, timestamp):
    """Persist an encrypted submission blob exactly as received (ciphertext only)."""
    cur = db.execute(
        "INSERT INTO responses (form_id, encrypted_data, encrypted_key, iv, nonce, timestamp)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (form_id, encrypted_data, encrypted_key, iv, nonce, timestamp),
    )
    db.commit()
    return cur.lastrowid


def get_responses(db, form_id):
    return db.execute(
        "SELECT * FROM responses WHERE form_id = ? ORDER BY id DESC", (form_id,)
    ).fetchall()


def get_response_with_owner(db, response_id):
    """A single response joined with its form's owner, for authorisation checks."""
    return db.execute(
        "SELECT r.*, f.owner_id FROM responses r JOIN forms f ON f.id = r.form_id"
        " WHERE r.id = ?",
        (response_id,),
    ).fetchone()


def delete_response(db, response_id):
    db.execute("DELETE FROM responses WHERE id = ?", (response_id,))
    db.commit()


# --------------------------------------------------------------- nonces

def register_nonce(db, nonce):
    """Atomically record a nonce. Returns False if it was already used.

    WHY at the database layer: the PRIMARY KEY constraint makes the
    check-and-insert a single atomic operation, so two concurrent replays of
    the same nonce cannot both slip through a check-then-act race.
    """
    try:
        db.execute("INSERT INTO nonces (nonce) VALUES (?)", (nonce,))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False
