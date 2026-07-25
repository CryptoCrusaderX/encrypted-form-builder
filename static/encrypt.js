/**
 * encrypt.js — client-side hybrid encryption for the Encrypted Form Builder.
 *
 * Everything here uses the browser's built-in Web Crypto API
 * (window.crypto / crypto.subtle) — no JavaScript crypto libraries.
 *
 * The scheme (mirrored exactly by crypto/decrypt.py on the server side,
 * which exists only so the tests can simulate a browser):
 *
 *   respondent's browser                         server
 *   --------------------                         ------
 *   random AES-256-GCM key  ──encrypts──▶ answers (ciphertext + tag)
 *   owner's RSA public key  ──wraps─────▶ that AES key (RSA-OAEP)
 *   POST { ciphertext, wrappedKey, iv, nonce, timestamp } ──▶ stored as-is
 *
 * The server never sees plaintext or an unwrapped AES key.
 */

/* ------------------------------------------------------------------ */
/* Encoding helpers: Web Crypto speaks ArrayBuffers, the wire speaks   */
/* base64 (JSON-safe) and keys travel as PEM text.                     */
/* ------------------------------------------------------------------ */

/**
 * Strip a PEM's header/footer/newlines and base64-decode the body,
 * yielding the raw DER bytes that crypto.subtle.importKey() expects.
 */
function pemToArrayBuffer(pem) {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(body); // base64 → binary string
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Encode an ArrayBuffer as base64 so it can travel inside JSON. */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/** Decode base64 from the server back into an ArrayBuffer for decryption. */
function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* ------------------------------------------------------------------ */
/* Key import                                                          */
/* ------------------------------------------------------------------ */

/**
 * Import the form owner's RSA public key (SPKI PEM from /public-key/<id>).
 *
 * - "spki" is the standard DER structure for public keys — it matches the
 *   SubjectPublicKeyInfo PEM the server produces with the pyca library.
 * - { name: "RSA-OAEP", hash: "SHA-256" } must match the server's OAEP
 *   parameters (MGF1-SHA256 + SHA256) or decryption would fail.
 * - extractable=false and usages=["encrypt"]: this key can only be used to
 *   encrypt in this page context, nothing else.
 */
async function importRsaPublicKey(pem) {
  return crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

/**
 * Import the owner's RSA private key (PKCS#8 PEM) for in-browser decryption.
 * The key arrives over the authenticated HTTPS session after the server
 * unlocked the owner's PKCS#12 keystore with their login password.
 * usages=["decrypt"] restricts what the imported handle can do.
 */
async function importRsaPrivateKey(pem) {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

/* ------------------------------------------------------------------ */
/* Encryption (respondent side)                                        */
/* ------------------------------------------------------------------ */

/**
 * Hybrid-encrypt the answers object for the holder of publicKeyPem.
 *
 * Steps, one Web Crypto call each:
 *  1. generateKey(AES-GCM 256)   — a fresh one-time symmetric key. AES does
 *     the heavy lifting because RSA can only encrypt ~190 bytes and is slow.
 *  2. getRandomValues(12 bytes)  — the GCM IV/nonce. 96 bits is the
 *     NIST-recommended GCM size; it must be unique per key (trivially true
 *     here, since the key itself is single-use).
 *  3. encrypt(AES-GCM)           — produces ciphertext WITH a 16-byte
 *     authentication tag appended. Any later bit-flip in the ciphertext
 *     makes decryption throw — that is the tamper-detection guarantee.
 *  4. exportKey("raw")           — the 32 raw AES key bytes, needed so we
 *     can wrap them with RSA.
 *  5. encrypt(RSA-OAEP)          — wraps the AES key under the owner's
 *     public key. Only the owner's private key can ever unwrap it.
 */
async function hybridEncrypt(publicKeyPem, answersObject) {
  const publicKey = await importRsaPublicKey(publicKeyPem);

  // (1) one-time AES-256-GCM key, extractable so step (4) can export it
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );

  // (2) 96-bit random IV from the browser CSPRNG
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // (3) encrypt the JSON-serialised answers; result includes the GCM auth tag
  const plaintext = new TextEncoder().encode(JSON.stringify(answersObject));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    plaintext
  );

  // (4) export the raw AES key bytes, then (5) wrap them with RSA-OAEP
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const wrappedKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawAesKey
  );

  return {
    encryptedData: arrayBufferToBase64(ciphertext),
    encryptedKey: arrayBufferToBase64(wrappedKey),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

/**
 * Encrypt the answers and POST the sealed envelope to /submit.
 *
 * Anti-replay fields added here:
 *  - nonce:     crypto.randomUUID() — a UUID4 the server stores and will
 *    never accept twice, so a captured request cannot be resubmitted.
 *  - timestamp: Date.now() (Unix ms) — the server rejects submissions older
 *    than 5 minutes, bounding how long a captured request stays usable and
 *    letting the server prune old nonces.
 */
async function encryptAndSubmit(formId, publicKeyPem, answersObject) {
  const envelope = await hybridEncrypt(publicKeyPem, answersObject);

  const response = await fetch("/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      formId: formId,
      ...envelope,
      nonce: crypto.randomUUID(),
      timestamp: Date.now(),
    }),
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || "Submission rejected by the server");
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* Decryption (form owner side)                                        */
/* ------------------------------------------------------------------ */

/**
 * Decrypt one stored response in the browser. The inverse of hybridEncrypt:
 *
 *  1. decrypt(RSA-OAEP) on the wrapped key — recovers the one-time AES key.
 *     Only works with the owner's private key; the server cannot do this.
 *  2. importKey("raw", AES-GCM) — turn the recovered bytes back into a key.
 *  3. decrypt(AES-GCM) — verifies the authentication tag FIRST, then
 *     decrypts. If the ciphertext, IV or tag were tampered with, this call
 *     rejects and we surface a tamper warning instead of garbage plaintext.
 */
async function decryptResponse(privateKey, response) {
  // (1) unwrap the one-time AES key with the owner's RSA private key
  const rawAesKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToArrayBuffer(response.encryptedKey)
  );

  // (2) re-import the raw bytes as a usable AES-GCM key handle
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  // (3) authenticated decryption — throws on any tampering
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToArrayBuffer(response.iv) },
    aesKey,
    base64ToArrayBuffer(response.encryptedData)
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}
