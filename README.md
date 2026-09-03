#  Encrypted Form Builder (krypto)
[![Python](https://img.shields.io/badge/python-3.11.5-red.svg)](https://python.org)
[![License MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)

#### *Krypto starts exactly where Google Forms stops being secure*

Krypto is an End-to-end encrypted form builder with PKI-based hybrid cryptography. Form responses are encrypted in the browser before they ever reach the server. 

## Why This Exists
Most form builders (Google Forms, Typeform, Jotform) store your data in plaintext in their server. The platform can read everything be it **medical histories, employee feedback, whistleblower reports.** If their database gets compromised, it's all your data that's going to be exposed.
Also there is a slight chance that the filled information (data) can be changed when data is in motion *(never say never)* and neither the form participant nor the form owner will know about that.

Krypto solves this by ensuring **only the form owner can decrypt all responses & If the data is modified in transit, the form owner will encounter a cryptographic failure when attempting to decrypt the response, indicating that the data may have been tampered with**

<p align="center">
  <img src="screenshots/homepage.jpg" width="800" alt="Krypto Homepage">
</p>

## Architecture

```mermaid
graph LR
    subgraph R["Respondent Browser"]
        R1["1. Fetch Owner's Public Key"]
        R2["2. Generate AES-256 Key + IV"]
        R3["3. AES-GCM Encrypt Answers"]
        R4["4. RSA-OAEP Wrap AES Key"]
        R5["5. Append Nonce + Timestamp"]
    end

    subgraph S["Flask Server"]
        S1["/public-key - Serve Public Key"]
        S2["Mini CA - X.509 Certificates"]
        S3["SQLite - Ciphertext Only"]
        S4["Replay + Freshness Checks"]
    end

    subgraph O["Owner Browser"]
        O1["6. Login Unlocks PKCS#12"]
        O2["7. Private Key Import"]
        O3["8. RSA-OAEP Unwrap AES Key"]
        O4["9. AES-GCM Decrypt"]
        O5["Plaintext ONLY in Browser"]
    end

    R5 -->|"POST /submit"| S4
    S1 --> R1
    S3 --> O1
    
    classDef client fill:#4488FF,color:white,stroke:#1A3A6B
    classDef server fill:#FF4444,color:white,stroke:#8B0000
    classDef db fill:#FF8844,color:white,stroke:#8B4500
    
    class R1,R2,R3,R4,R5 client
    class O1,O2,O3,O4,O5 client
    class S1,S2,S4 server
    class S3 db
```
## Setup

**1. Clone the repository**
```bash
git clone https://github.com/CryptoCrusaderX/encrypted-form-builder.git
cd encrypted-form-builder
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate     # On Windows
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Initialize the database**
```bash
flask shell
>>> from models import init_db
>>> init_db()
>>> exit()
```

**5. Run the application**
```bash
flask run
```

Open `http://127.0.0.1:5000` in your browser.

> **Note:** The first user to register becomes the form owner. Subsequent users can fill forms but cannot create them.

## Features

- **End-to-end encryption**
  - AES-256-GCM encrypts data in the browser before submission.
  - RSA-2048-OAEP wraps the AES key using the owner's public key.
  - Server stores ciphertext only — plaintext never touches the server.

- **PKI infrastructure**
  - Mini Certificate Authority issues X.509 certificates for every user.
  - Private keys stored inside password-encrypted PKCS#12 keystores.

- **Form lifecycle & access control**
  - Retire forms to stop submissions. Delete individual responses.
  - Users must register to fill forms. Owners cannot submit to their own.

- **Replay & tamper protection**
  - UUID4 nonces + 5-minute freshness window prevent replay attacks.
  - AES-GCM authentication tags detect ciphertext modification.

## Testing

Run the test suite to verify functionality and attack simulations:

```bash
pytest tests/
```



## License

[MIT](LICENSE)
