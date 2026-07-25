# 🔐 Krypto

A PKI-based, end-to-end encrypted form application built for **ST6051CEM
Practical Cryptography** (Softwarica College / Coventry University).

Form responses are encrypted **in the respondent's browser** using hybrid
cryptography — AES-256-GCM for the data, RSA-2048-OAEP to wrap the AES key —
via the native Web Crypto API. The Flask server stores **ciphertext only**:
even a complete database breach reveals nothing readable. A mini Certificate
Authority signs every user's public key into an X.509 certificate, and private
keys rest only inside password-encrypted PKCS#12 keystores.

## Architecture

```
  RESPONDENT'S BROWSER                    FLASK SERVER                FORM OWNER'S BROWSER
 ┌──────────────────────┐          ┌───────────────────────┐        ┌──────────────────────┐
 │ 1. fetch owner's     │◀────────▶│  /public-key/<id>     │        │ 6. login unlocks     │
 │    certified pub key │          │  (cert chain checked  │        │    PKCS#12 keystore  │
 │                      │          │   against mini CA)    │        │    with password     │
 │ 2. random AES-256    │          │                       │        │                      │
 │    key + 96-bit IV   │          │  ┌─────────────────┐  │  HTTPS │ 7. private key PEM   │
 │                      │          │  │   Mini CA (X.509)│  │──────▶│    imported via      │
 │ 3. AES-GCM encrypt   │          │  │   root + user    │  │        │    Web Crypto        │
 │    answers ────────┐ │          │  │   certificates   │  │        │                      │
 │                    │ │          │  └─────────────────┘  │        │ 8. RSA-OAEP unwraps  │
 │ 4. RSA-OAEP wrap   │ │          │                       │        │    the AES key       │
 │    AES key ────────┤ │  POST    │  ┌─────────────────┐  │        │                      │
 │                    │ │ /submit  │  │  SQLite: users,  │  │        │ 9. AES-GCM decrypts  │
 │ 5. + nonce (UUID4) ├─┼─────────▶│  │  forms,          │──┼───────▶│    (auth tag proves  │
 │    + timestamp     │ │          │  │  CIPHERTEXT only,│  │        │    integrity)        │
 └────────────────────┴─┘          │  │  nonces          │  │        │                      │
                                   │  └─────────────────┘  │        │ plaintext exists     │
        server never sees ─────────▶  replay + freshness    │        │ ONLY in the browser  │
        plaintext or AES keys      │  checks on /submit     │        └──────────────────────┘
                                   └───────────────────────┘
```

## Quick start

```bash
pip install -r requirements.txt
flask run
```

Then open <http://127.0.0.1:5000>, register (this generates your RSA keypair,
CA-signed certificate and PKCS#12 keystore), create a form, and share its
fill-in link (`http://127.0.0.1:5000/form/<uuid>`). Respondents must register
and log in before they can submit. Note: in real deployments the app must sit
behind **HTTPS** — the private-key delivery to the owner's browser depends on
transport security.

## Features

- **Owner dashboard** — every form as a card with its response count,
  active/retired status, share-link copy button, and one-click deletion
  (removes the form and all of its responses).
- **Unguessable form links** — forms are addressed by UUID4 only, so response
  and fill-in URLs cannot be enumerated (IDOR defence). Response pages are
  strictly owner-only (403 otherwise).
- **Form lifecycle** — retire a form to stop accepting submissions (respondents
  see a "form closed" page); delete individual responses from the accordion
  view of decrypted answers.
- **Access control** — filling a form requires an account, and owners cannot
  submit responses to their own forms.

## Running the tests

```bash
pytest tests/
```

- `tests/test_crypto.py` — unit tests for key generation, certificate
  issuance/verification, PKCS#12 round-trips and hybrid encryption.
- `tests/test_attacks.py` — attack simulations against the live app:
  **replay** (reused nonce → HTTP 400), **tampering** (bit-flipped ciphertext
  → AES-GCM `InvalidTag`), **rogue CA** (foreign certificate fails chain
  validation), **stale capture** (timestamp older than 5 minutes → HTTP 400),
  plus a database-dump test proving no plaintext is ever stored.

## Security design

| Threat | Defence |
|---|---|
| Database breach | Client-side encryption; server stores AES-GCM ciphertext + RSA-wrapped keys only |
| Replay attack | UUID4 nonce (DB-enforced uniqueness) + 5-minute timestamp freshness window |
| MITM / key substitution | X.509 certificates chained to the mini CA root; unverifiable keys are never served |
| Ciphertext tampering | AES-GCM authentication tag — any modification makes decryption fail loudly |
| Private key theft at rest | Keys exist only inside PKCS#12 keystores encrypted with the user's password |
| IDOR / URL enumeration | Forms addressed by UUID4 only; response pages enforce ownership (403) |

## Use cases

1. **Medical questionnaires** — patients submit symptoms and history that
   only the requesting clinician can decrypt; the clinic's server, IT staff
   and backups hold ciphertext only, supporting confidentiality obligations.
2. **Whistleblower reports** — sources submit disclosures encrypted to a
   journalist's or ombudsman's key; even a subpoena or seizure of the server
   cannot expose the report's contents.
3. **University exam feedback** — students give candid module feedback that
   only the course leader can read, with the replay protection preventing
   ballot-stuffing of duplicate submissions.

## Project layout

```
app.py            Flask routes (thin — no crypto logic here)
models.py         SQLite persistence (raw sqlite3, parameterised queries)
crypto/ca.py      Mini X.509 Certificate Authority
crypto/keys.py    RSA keypair + PKCS#12 keystore handling
crypto/decrypt.py Hybrid AES-GCM / RSA-OAEP (Python mirror of the browser flow)
static/encrypt.js All client-side Web Crypto operations, fully commented
templates/        Bootstrap 5 UI
tests/            Unit tests + attack simulations (pytest)
```

## Acknowledgements

Built with [Claude Code](https://claude.com/claude-code).

## License

[MIT](LICENSE)
