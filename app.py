"""Flask application for Krypto — the encrypted form builder.

Routes are intentionally thin: every cryptographic operation lives in the
``crypto`` package and every database operation in ``models``. The server's
security posture in one sentence: it stores ciphertext, wrapped keys and
password-encrypted keystores — it never stores, logs or renders plaintext
form answers or raw private keys.

Access-control rules enforced here:

- Forms are addressed exclusively by UUID4 (unguessable URLs, no IDOR).
- Filling a form requires being logged in; owners cannot fill (or submit to)
  their own forms.
- Response pages, retirement, and deletion are owner-only (403 otherwise).
"""

import base64
import binascii
import json
import os
import secrets
import time
import uuid
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import models
from crypto import keys as key_utils
from crypto.ca import CertificateAuthority

# Anti-replay window: a submission's client timestamp must be at most this
# old. 5 minutes tolerates slow connections while keeping the window a
# captured request can be replayed in (before the nonce check even applies)
# short. A small forward skew is allowed for slightly-fast client clocks.
REPLAY_WINDOW_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 60

# Unlocked private keys, held in server memory only (never persisted), keyed
# by a random per-login token stored in the user's session cookie. Cleared on
# logout and lost on restart — by design, the decrypted key has no durable home.
_PRIVATE_KEY_CACHE = {}


def _timestamp_is_fresh(timestamp_ms):
    """Check the client timestamp is within the anti-replay window.

    WHY: the nonce table only stops replays of nonces we have *seen*. The
    timestamp bound additionally rejects very old captured requests outright
    and lets the nonce table be pruned safely after the window passes.
    """
    age_seconds = time.time() - (timestamp_ms / 1000.0)
    return -MAX_CLOCK_SKEW_SECONDS <= age_seconds <= REPLAY_WINDOW_SECONDS


def _safe_next_url(candidate):
    """Only allow same-site relative redirect targets (no open redirects)."""
    return candidate if candidate and candidate.startswith("/") and not candidate.startswith("//") else None


def create_app(instance_path=None):
    """Application factory (used by ``flask run`` and by the test suite)."""
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    os.makedirs(app.instance_path, exist_ok=True)

    # Session-signing secret: from the environment if provided, otherwise a
    # random value generated once and persisted in the git-ignored instance
    # dir. Never hardcoded in source.
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        secret_file = os.path.join(app.instance_path, "secret_key")
        if os.path.exists(secret_file):
            with open(secret_file) as fh:
                secret = fh.read().strip()
        else:
            secret = secrets.token_hex(32)
            with open(secret_file, "w") as fh:
                fh.write(secret)
            os.chmod(secret_file, 0o600)
    app.secret_key = secret

    app.config["DATABASE"] = os.path.join(app.instance_path, "forms.db")
    models.init_db(app.config["DATABASE"])

    # The mini CA lives in the instance dir; created on first boot, stable after.
    ca = CertificateAuthority(os.path.join(app.instance_path, "ca"))
    app.config["CA"] = ca

    app.teardown_appcontext(models.close_db)

    def db():
        return models.get_db(app.config["DATABASE"])

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def share_link(form_uuid):
        """Absolute respondent URL, e.g. http://127.0.0.1:5000/form/<uuid>."""
        return url_for("fill_form", form_uuid=form_uuid, _external=True)

    def error_page(status, title, message):
        return render_template("error.html", title=title, message=message), status

    # ------------------------------------------------------------ pages

    @app.route("/")
    def index():
        """Landing page for visitors; logged-in users go to their dashboard."""
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """The owner's forms with response counts, status and share links."""
        forms = models.get_forms_by_owner(db(), session["user_id"])
        return render_template("dashboard.html", forms=forms, share_link=share_link)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """Create an account and its full PKI identity in one step:
        RSA keypair → CA-signed certificate → PKCS#12 keystore in the DB."""
        if request.method == "GET":
            return render_template("register.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or len(password) < 8:
            flash("Username is required and the password must be at least 8 characters.", "danger")
            return render_template("register.html"), 400

        # 1. Fresh RSA-2048 keypair for this user.
        private_key = key_utils.generate_rsa_keypair()
        # 2. Mini CA binds the public key to the username in an X.509 cert.
        certificate = ca.issue_certificate(private_key.public_key(), username)
        # 3. Key + cert sealed into a PKCS#12 keystore under the user's password.
        keystore = key_utils.create_pkcs12_keystore(
            private_key, certificate, password, ca_cert=ca.cert
        )

        user_id = models.create_user(
            db(),
            username,
            generate_password_hash(password),
            keystore,
            key_utils.certificate_to_pem(certificate),
            key_utils.public_key_to_pem(private_key.public_key()),
        )
        if user_id is None:
            flash("That username is already taken.", "danger")
            return render_template("register.html"), 400

        flash("Account created — your keypair and certificate were generated. Please log in.", "success")
        return redirect(url_for("login", next=request.args.get("next")))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Verify credentials, then unlock the PKCS#12 keystore with the same
        password and cache the private key in server memory for this session."""
        if request.method == "GET":
            return render_template("login.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = models.get_user_by_username(db(), username)
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        try:
            private_key, _cert = key_utils.load_pkcs12_keystore(user["keystore"], password)
        except ValueError:
            # Wrong PKCS#12 password despite a matching hash should be impossible;
            # treat it as a corrupted keystore rather than logging the user in.
            flash("Your keystore could not be unlocked. Contact the administrator.", "danger")
            return render_template("login.html"), 500

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        # Random token → in-memory key cache; the key itself never enters the cookie.
        token = secrets.token_urlsafe(32)
        session["key_token"] = token
        _PRIVATE_KEY_CACHE[token] = key_utils.private_key_to_pem(private_key)

        flash("Logged in. Your private key is unlocked for this session.", "success")
        next_url = _safe_next_url(request.form.get("next"))
        return redirect(next_url or url_for("dashboard"))

    @app.route("/logout")
    def logout():
        """End the session and wipe the unlocked private key from memory."""
        _PRIVATE_KEY_CACHE.pop(session.get("key_token"), None)
        session.clear()
        flash("Logged out — your private key was wiped from server memory.", "info")
        return redirect(url_for("login"))

    @app.route("/create-form", methods=["GET", "POST"])
    @login_required
    def create_form():
        """Define a form: a title, a description and one field label per line."""
        if request.method == "GET":
            return render_template("create_form.html")

        title = (request.form.get("title") or "").strip()
        fields = [
            line.strip()
            for line in (request.form.get("fields") or "").splitlines()
            if line.strip()
        ]
        if not title or not fields:
            flash("A title and at least one field are required.", "danger")
            return render_template("create_form.html"), 400

        form_uuid = str(uuid.uuid4())
        models.create_form(
            db(),
            form_uuid,
            session["user_id"],
            title,
            (request.form.get("description") or "").strip(),
            json.dumps(fields),
        )
        return redirect(url_for("form_created", form_uuid=form_uuid))

    @app.route("/form-created/<form_uuid>")
    @login_required
    def form_created(form_uuid):
        """Success page after creating a form, with the shareable link."""
        form = models.get_form_by_uuid(db(), form_uuid)
        if form is None or form["owner_id"] != session["user_id"]:
            return error_page(404, "Form not found", "That form does not exist.")
        return render_template(
            "form_created.html", form=form, share_link=share_link(form_uuid)
        )

    @app.route("/form/<form_uuid>")
    def fill_form(form_uuid):
        """Fill-in page for logged-in respondents. All encryption happens in
        the visitor's browser. Owners are redirected to their responses."""
        if "user_id" not in session:
            flash("Please register or log in to fill this form.", "warning")
            return redirect(url_for("login", next=request.path))

        form = models.get_form_by_uuid(db(), form_uuid)
        if form is None:
            return error_page(404, "Form not found", "That form does not exist. Check the link you were given.")

        if form["owner_id"] == session["user_id"]:
            flash("You can't fill your own form.", "warning")
            return redirect(url_for("view_responses", form_uuid=form_uuid))

        if not form["is_active"]:
            return render_template("form_closed.html", form=form)

        return render_template(
            "fill_form.html", form=form, fields=json.loads(form["fields"])
        )

    @app.route("/responses/<form_uuid>")
    @login_required
    def view_responses(form_uuid):
        """Owner-only: ship the ciphertext blobs plus the session-unlocked
        private key to the browser, which performs all decryption locally."""
        form = models.get_form_by_uuid(db(), form_uuid)
        if form is None:
            return error_page(404, "Form not found", "That form does not exist.")
        if form["owner_id"] != session["user_id"]:
            return error_page(403, "403 — Forbidden", "Only the form owner can view its responses.")

        private_key_pem = _PRIVATE_KEY_CACHE.get(session.get("key_token"))
        if private_key_pem is None:
            # e.g. server restarted since login — the cache is memory-only.
            flash("Your session key expired. Please log in again to decrypt responses.", "warning")
            return redirect(url_for("login"))

        responses = [
            {
                "id": r["id"],
                "encryptedData": r["encrypted_data"],
                "encryptedKey": r["encrypted_key"],
                "iv": r["iv"],
                "submittedAt": r["submitted_at"],
            }
            for r in models.get_responses(db(), form["id"])
        ]
        return render_template(
            "view_responses.html",
            form=form,
            fields=json.loads(form["fields"]),
            responses=responses,
            private_key_pem=private_key_pem,
            share_link=share_link(form_uuid),
        )

    @app.post("/form/<form_uuid>/retire")
    @login_required
    def retire_form(form_uuid):
        """Owner-only: stop accepting responses; respondents see a closed page."""
        form = models.get_form_by_uuid(db(), form_uuid)
        if form is None:
            return error_page(404, "Form not found", "That form does not exist.")
        if form["owner_id"] != session["user_id"]:
            return error_page(403, "403 — Forbidden", "Only the form owner can retire this form.")

        models.set_form_active(db(), form["id"], False)
        flash("Form retired — respondents now see a 'form closed' page.", "success")
        return redirect(url_for("view_responses", form_uuid=form_uuid))

    @app.post("/form/<form_uuid>/delete")
    @login_required
    def delete_form(form_uuid):
        """Owner-only: delete the form and every response submitted to it."""
        form = models.get_form_by_uuid(db(), form_uuid)
        if form is None:
            return error_page(404, "Form not found", "That form does not exist.")
        if form["owner_id"] != session["user_id"]:
            return error_page(403, "403 — Forbidden", "Only the form owner can delete this form.")

        models.delete_form(db(), form["id"])
        flash(f"Form “{form['title']}” and all its responses were deleted.", "success")
        return redirect(url_for("dashboard"))

    # -------------------------------------------------------------- API

    @app.delete("/response/<int:response_id>")
    def delete_response(response_id):
        """Owner-only: delete a single response (called from the responses page)."""
        if "user_id" not in session:
            return jsonify({"error": "You must be logged in"}), 401

        row = models.get_response_with_owner(db(), response_id)
        if row is None:
            return jsonify({"error": "Unknown response"}), 404
        if row["owner_id"] != session["user_id"]:
            return jsonify({"error": "Only the form owner can delete responses"}), 403

        models.delete_response(db(), response_id)
        return jsonify({"status": "ok"})

    @app.post("/submit")
    def submit():
        """Accept an encrypted submission. The server validates transport-level
        properties (shape, freshness, nonce uniqueness) and access rules, but
        can not — and does not try to — read the payload."""
        if "user_id" not in session:
            return jsonify({"error": "Please register or log in to fill this form"}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Expected a JSON body"}), 400

        required = ["formId", "encryptedData", "encryptedKey", "iv", "nonce", "timestamp"]
        missing = [f for f in required if f not in payload]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        form = models.get_form_by_uuid(db(), str(payload["formId"]))
        if form is None:
            return jsonify({"error": "Unknown form"}), 404
        if not form["is_active"]:
            return jsonify({"error": "This form is closed and no longer accepts responses"}), 403
        if form["owner_id"] == session["user_id"]:
            return jsonify({"error": "You can't submit a response to your own form"}), 403

        # The blobs must at least be valid base64 (checked before the nonce is
        # consumed, so a malformed request cannot burn a nonce).
        try:
            for field in ("encryptedData", "encryptedKey", "iv"):
                base64.b64decode(payload[field], validate=True)
        except (binascii.Error, TypeError, ValueError):
            return jsonify({"error": "Ciphertext fields must be valid base64"}), 400

        # Anti-replay check 1: the nonce must be a well-formed UUID.
        try:
            uuid.UUID(str(payload["nonce"]))
        except ValueError:
            return jsonify({"error": "Nonce must be a UUID"}), 400

        # Anti-replay check 2: the timestamp must be inside the freshness window.
        try:
            timestamp_ms = int(payload["timestamp"])
        except (TypeError, ValueError):
            return jsonify({"error": "Timestamp must be an integer (Unix ms)"}), 400
        if not _timestamp_is_fresh(timestamp_ms):
            return jsonify({"error": "Rejected: timestamp outside the 5-minute freshness window"}), 400

        # Anti-replay check 3: the nonce must never have been seen before.
        # Uniqueness is enforced atomically by the database primary key.
        if not models.register_nonce(db(), str(payload["nonce"])):
            return jsonify({"error": "Rejected: replay detected (nonce already used)"}), 400

        response_id = models.store_response(
            db(),
            form["id"],
            payload["encryptedData"],
            payload["encryptedKey"],
            payload["iv"],
            str(payload["nonce"]),
            timestamp_ms,
        )
        return jsonify({"status": "ok", "responseId": response_id}), 201

    @app.get("/public-key/<int:user_id>")
    def public_key(user_id):
        """Serve a user's RSA public key (SPKI PEM) plus their certificate.

        Respondents' browsers fetch this before encrypting. The certificate is
        included, already verified against the mini CA, so a key that does not
        chain to our root is never handed out — the MITM defence.
        """
        user = models.get_user_by_id(db(), user_id)
        if user is None:
            return jsonify({"error": "Unknown user"}), 404

        valid, reason = ca.verify_certificate(
            key_utils.certificate_from_pem(user["certificate"])
        )
        if not valid:
            return jsonify({"error": f"Certificate failed chain validation: {reason}"}), 409

        return jsonify(
            {
                "userId": user["id"],
                "publicKey": user["public_key"],
                "certificate": user["certificate"],
            }
        )

    @app.get("/verify-cert")
    def verify_cert():
        """Validate a user's certificate against the mini CA root.

        ``GET /verify-cert?user_id=N`` → JSON verdict with subject/issuer
        details, or the root CA certificate itself when called with no args.
        """
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"rootCertificate": ca.root_certificate_pem()})

        user = models.get_user_by_id(db(), user_id)
        if user is None:
            return jsonify({"error": "Unknown user"}), 404

        cert = key_utils.certificate_from_pem(user["certificate"])
        valid, reason = ca.verify_certificate(cert)
        return jsonify(
            {
                "userId": user["id"],
                "valid": valid,
                "reason": reason,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "notAfter": cert.not_valid_after_utc.isoformat(),
            }
        )

    return app


# `flask run` auto-discovers this module-level app; tests build their own
# isolated instances via create_app(instance_path=...).
app = create_app()
