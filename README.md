# SecureVault

**ENCS4320 – Applied Cryptography, Term 1253**  
**Birzeit University – Electrical and Computer Engineering Department**

SecureVault is our multi-user encrypted document exchange system. Users can register and log in, encrypt documents locally, store only the encrypted document objects on the server, and share access with other users.

Our implementation uses a command-line client and a shared-directory transport to simulate the network.

---

## Team

| Member | Student ID | Main contribution |
|---|---:|---|
| Aseel Hamed | 1231891 | Part 1 — accounts, password derivation, RSA-PSS, HMAC/HKDF, private-key protection, registration/login/sessions/password change |
| Ruaa Othman | 1230014 | Part 2 — SHA-256, ChaCha20, Poly1305, AEAD, formats, transport, client/server integration |
| Yaqeen Salameh | 1230011 | Part 3 — P-256, ECDH, TOFU trust, sharing, freshness/replay protection |

---

## Main Security Design

- **Passwords:** Argon2id with a fresh 16-byte salt, followed by HKDF-SHA-256 with separate labels for authentication and private-key wrapping.
- **Document protection:** ChaCha20-Poly1305 with a fresh 32-byte document key and fresh 12-byte nonce.
- **Signatures:** RSA-PSS with 3072-bit RSA keys.
- **Key agreement:** P-256 ECDH followed by HKDF-SHA-256.
- **Trust:** Trust On First Use (TOFU) with SHA-256 fingerprints over the canonical public-key record.
- **Replay protection:** one-time login challenges, per-session request IDs, and per-sender/per-document freshness state for shares.
- **Metadata binding:** cleartext metadata is authenticated through AEAD associated data and/or signed bytes.

---

## Repository Structure

```text
SecureVault/
├── client.py
├── server.py
├── transport.py
├── accounts.py
├── account_store.py
├── account_messages.py
├── person1_interfaces.py
├── private_keys.py
├── sharing.py
├── trust.py
├── freshness.py
├── test_system.py
├── requirements.txt
├── requirements-dev.txt
├── crypto/
│   ├── sha256.py
│   ├── chacha20.py
│   ├── poly1305.py
│   ├── aead.py
│   ├── rsa_pss.py
│   ├── hmac_hkdf.py
│   ├── p256.py
│   └── formats.py
├── tests/
├── benchmarks/
└── docs/
```

Runtime directories such as `client_local/`, `shared_network/`, `server_private/`, and `server_storage/` are created while the program runs.

`person1_interfaces.py` contains the shared Part 1 interface used across module boundaries; for example, the sharing code imports the account/key interfaces it needs from this module.

---

## Requirements

A Python 3 environment is required.

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install runtime dependencies:

```powershell
python -m pip install -r requirements.txt
```

For running the test suite, install the development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

`requirements.txt` includes `argon2-cffi`.  
`requirements-dev.txt` additionally includes `pytest` and `cryptography`; the `cryptography` package is used only in tests for reference cross-checks, not as the submitted implementation of the team-written cryptographic primitives.

---

## Running SecureVault

All commands below are run from the project root.

Steps 2 to 9 assume the server from step 1 is still running. Each user must be logged in before uploading, sharing, receiving, or downloading.

### 1. Start the server

Open the first terminal:

```powershell
python server.py
```

Keep this terminal running.

### 2. Register users

Open another terminal:

```powershell
python client.py register layla <password>
python client.py register omar <password>
```

Registration generates each user's RSA-3072 and P-256 identity keys locally. Private identity keys are wrapped before server storage; they are not committed to the repository.

### 3. Log in

```powershell
python client.py login layla <password>
python client.py login omar <password>
```

Logging in prints the account's public-key fingerprint. Before two users share a document for the first time, they should compare these fingerprints through a channel other than the server.

### 4. Upload a document

```powershell
python client.py upload <file_path> layla
```

The client prints the generated document ID. Keep that ID for the following commands.

Example:

```powershell
python client.py upload thesis-draft.pdf layla
```

### 5. Share the document

```powershell
python client.py share <document_id> layla omar
```

The sender creates an ephemeral P-256 key pair, derives a wrapping key through ECDH + HKDF, wraps the document key, and signs the Share object with RSA-PSS.

### 6. Receive the share

On Omar's side:

```powershell
python client.py receive omar
```

The client checks trust/fingerprint information, verifies the RSA-PSS signature, checks freshness, and unwraps the document key if verification succeeds.

### 7. Download and decrypt the document

```powershell
python client.py download <document_id> omar <output_path>
```

Example:

```powershell
python client.py download <document_id> omar recovered-file.pdf
```

The AEAD tag is verified before plaintext is written.

### 8. Change a password

```powershell
python client.py change-password layla <old_password> <new_password>
```

The same RSA and P-256 identity keys are preserved and re-wrapped under a newly derived wrap key. Existing sessions for that user are invalidated.

### 9. Log out

```powershell
python client.py logout layla
```

---

## Running the Tests

Run the complete pytest suite:

```powershell
python -m pytest -q tests
```

The complete suite currently reports **237 passed with 158 subtests**. A full run takes about **35 minutes** on our test machine, mostly because RSA-3072 key generation is intentionally expensive.

Run the complete full-system test runner:

```powershell
python test_system.py
```

`test_system.py` first runs the complete pytest suite, then starts the real server and executes a Layla-to-Omar application flow using the real client, transport, account, sharing, trust, and freshness code.

The full-system runner checks the honest path and negative/security cases including:

- registration and login for two users,
- encrypted upload and successful retrieval,
- secure sharing and receiving,
- replay rejection,
- stored-document tampering rejection,
- Share tampering rejection,
- TOFU public-key substitution rejection,
- absence of raw plaintext in server document storage,
- logout and local session cleanup.

---

## Cryptographic Implementation and Library Use

The team implemented the main cryptographic components used by SecureVault, including:

- SHA-256,
- HMAC-SHA-256,
- HKDF-SHA-256,
- ChaCha20,
- Poly1305,
- ChaCha20-Poly1305 AEAD,
- RSA-3072 key generation,
- Miller-Rabin primality testing,
- MGF1 and RSA-PSS,
- P-256 arithmetic, key generation, public-key validation, and ECDH,
- object formats, sharing, trust, and freshness logic.

Argon2id is used through `argon2-cffi`.

Operating-system randomness, Python big integers, SQLite, JSON, file handling, and pytest are support components rather than cryptographic primitive implementations.

Reference cryptographic libraries are used only inside tests to compare outputs.

---

## Generated Secrets and Repository Safety

Do **not** commit passwords, private keys, session material, or other generated secrets.

SecureVault generates cryptographic keys and random values locally at runtime. No pre-generated user private keys are required.

The following runtime locations may contain sensitive or user-specific state and should not be committed:

```text
client_local/
server_private/
server_storage/
shared_network/
```

In particular, `client_local/` may contain active session state and recovered client-side secret material during a running/demo session.

A suitable `.gitignore` should exclude those runtime directories as well as the local virtual environment:

```gitignore
.venv/
__pycache__/
.pytest_cache/

client_local/
shared_network/
server_private/
server_storage/
```

---

## Threat-Model Boundary

SecureVault assumes an honest user's client machine is trustworthy. The server is honest-but-curious, the network may be attacker-controlled, and server storage may be stolen.

The current project does not attempt to defend against malware on the user's own machine, user coercion, traffic analysis, or denial of service.

---

## Known Limitations

These are the main limitations we are aware of in the current implementation:

- TOFU does not authenticate the first public key without an out-of-band comparison.
- A stolen stored login verifier can be used for impersonation in the current symmetric HMAC login design.
- The current Share signature authenticates the share/key grant but does not commit to a hash of the complete Document object.
- The simulated shared-directory message envelope does not authenticate the reply address.
- Active client-side session/wrap/identity material should use protected OS storage or in-memory handling in a production system.
- Random nonces provide probabilistic rather than mathematical uniqueness.

See the design report for the complete security argument, design rationale, and limitations.

---

## Project Documents

The repository contains:

- source code,
- the test suite,
- this README,
- the final design report,
- the presentation slides.
