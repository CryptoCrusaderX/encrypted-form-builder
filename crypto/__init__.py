"""Cryptographic core of the Encrypted Form Builder.

This package isolates ALL cryptographic logic from the web layer:

- ``ca``      : a mini Certificate Authority (X.509 root + user certificates)
- ``keys``    : RSA keypair generation and PKCS#12 keystore handling
- ``decrypt`` : hybrid AES-GCM / RSA-OAEP helpers (mirrors the browser's
                Web Crypto API operations, used by the server-side tests)

Flask routes in ``app.py`` only *call* these functions; they never touch
primitives directly. This separation is deliberate: crypto code is easy to
get subtly wrong, so keeping it in one reviewable place reduces the chance
of a mistake hiding inside unrelated request-handling code.
"""
