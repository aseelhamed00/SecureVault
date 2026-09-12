# Account Interface Agreement

We use this document to keep our three parts of SecureVault consistent. It records our shared function interfaces, data formats, and account rules.

## 1. General Conventions

- We use `bytes` for cryptographic messages, digests, tags, and derived values.
- Usernames and passwords enter the application as strings. We encode usernames as UTF-8 before passing them to cryptographic functions.
- RSA key components are Python integers in memory.
- Hexadecimal output is used for display and test vectors.
- Shared objects use a common serialization interface.
- Verification failure returns neither plaintext nor private keys.
- Cryptographic primitives retain their standard internal byte ordering.

## 2. Account Interfaces

Responsible team member: Person 1

| Function | Inputs | Successful result |
|---|---|---|
| `register` | Username and password | Identifies the registered user |
| `login` | Username and password | Authenticated client session context |
| `change_password` | Session context, old password, new password | Confirms a consistent password update |
| `logout` | Session context | Invalidates the session; no return value |

We call these functions from the client. The session stays on the client; we do not send the full session object over the shared directory.

### Session representation

We create a client session after a successful login.

| Field | Type |
|---|---|
| `user_id` | bytes |
| `username` | str |
| `rsa_private` | dict with `n`, `e`, `d`, `p`, `q` |
| `p256_private` | 32-byte scalar |
| `created_at` | timestamp |
| `expires_at` | `created_at` + 15 minutes |

Sessions expire 15 minutes after login and are not renewed by activity; the
user logs in again. `logout` invalidates the session immediately. An expired or
invalidated session is treated as no session at all. We keep recovered private keys in the session and release our references to them when the session ends. This does not guarantee that Python overwrites their bytes in memory.

## 3. Cryptographic Interfaces

| Function | Inputs | Output | Owner |
|---|---|---|---|
| `sha256` | Data bytes | 32-byte digest | Person 2 |
| `hmac_sha256` | Key bytes, data bytes | 32-byte tag | Person 1 |
| `compare_tags` | Two byte values | Boolean | Person 1 |
| `hkdf_extract` | Salt bytes, IKM bytes | 32-byte PRK | Person 1 |
| `hkdf_expand` | PRK bytes, info bytes, output length | Derived bytes | Person 1 |
| `hkdf` | IKM bytes, salt bytes, info bytes, output length | Derived bytes | Person 1 |
| `rsa_keygen` | No arguments | `(private_key, public_key)` | Person 1 |
| `pss_sign` | RSA private key, message bytes | 384-byte signature | Person 1 |
| `pss_verify` | RSA public key, message bytes, signature bytes | Boolean | Person 1 |
| `p256_keygen` | No application input | P-256 private/public key pair | Person 3 |
| `aead_encrypt` | Key, nonce, AAD, plaintext as bytes | Separate ciphertext and tag | Person 2 |
| `aead_decrypt` | Key, nonce, AAD, ciphertext, tag as bytes | Verified plaintext or failure | Person 2 |

We call SHA-256 through `sha256(data)`. The current wrapper calls `SHA_256(message)` and returns a 32-byte digest. Person 2 is responsible for the shared SHA-256 module.

## 4. RSA Key Generation and Signatures

### Key generation

- Modulus size: exactly 3072 bits.
- Public exponent: `65537`.
- Prime candidate size: 1536 bits for each factor.
- Primality test: Miller–Rabin with 64 random rounds, preceded by small-prime checks.
- Randomness: the operating system's cryptographic random source through `secrets`.
- The factors `p` and `q` must differ.
- `n = p * q`.
- `lambda_n = lcm(p - 1, q - 1)`.
- `gcd(e, lambda_n) = 1`.
- `d` is the modular inverse of `e` modulo `lambda_n`.

| Key | Local representation |
|---|---|
| Public | Dictionary containing `n` and `e` |
| Private | Dictionary containing `n`, `e`, `d`, `p`, and `q` |

We use these dictionaries in memory. They do not define the serialized private-key format.

### RSA-PSS parameters

- RSA-3072.
- SHA-256.
- MGF1-SHA-256.
- Fresh 32-byte random salt.
- 384-byte signature.
- Verification returns `True` or `False` and accepts only the agreed 32-byte salt length.
- `pss_sign(private_key, message)` generates its own salt. Fixed salts are used only in tests of the internal encoding function.

### Key-generation tests

Tests cover known primes and composites, invalid parameters, independently checked small primes, key sizes and mathematical relationships, two independent key pairs, reference-library validation, and rejection of a corrupted private key.

For RSA, SHA-256, HMAC, and HKDF, we use reference libraries only in tests to compare their results with ours. Argon2id is our separate library-based component.

### Signature tests

We test MGF1 outputs, signing and verification, compatibility with the reference library in both directions, and rejection of changed messages, wrong keys, malformed signatures, and incorrect salt lengths.

## 5. Password Protection

- Password derivation uses Argon2id through `argon2-cffi`.
- Each account receives a fresh 16-byte salt from OS cryptographic randomness.
- The credential record stores the salt and Argon2id parameters.
- Performance measurements determine the Argon2id work settings.
- The private-key wrapping key remains client-side.

- HKDF-SHA-256 derives the authentication and wrapping values from the
  Argon2id output, which is used directly as the HKDF input keying material.
- We use an empty HKDF salt for account-key derivation. Its input is the Argon2id output. We use different purpose labels to separate the authentication value from the wrapping key.

| Derived value | Label | Length |
|---|---|---|
| Authentication value | `b"securevault:v1:auth"` | 32 bytes |
| Private-key wrapping key | `b"securevault:v1:wrap"` | 32 bytes |

### HMAC and HKDF implementation

We implement these functions in `crypto/hmac_hkdf.py` using our shared `sha256` interface.

- HMAC-SHA-256 uses a 64-byte block and produces a 32-byte tag. We hash keys longer than 64 bytes before padding them.
- We compare the computed tag with the received tag using `compare_tags`, which calls `secrets.compare_digest`.
- `hkdf_extract(salt, ikm)` uses 32 zero bytes when the salt is empty or `None`.
- `hkdf_expand(prk, info, length)` requires a PRK of at least 32 bytes. Empty info is allowed; `None` is treated as empty info.
- Output length must be an integer from 0 to 8160 bytes. Boolean values are rejected. Length 0 returns empty bytes.
- `hkdf(ikm, salt, info, length)` runs Extract followed by Expand.

We test published RFC 4231 HMAC-SHA-256 vectors and RFC 5869 HKDF-SHA-256 vectors, compare results with reference libraries, and check altered tags, key lengths, purpose labels, invalid output lengths, and short PRKs.

## 6. Account Records

We start shared objects with version and type fields. We use 4-byte length prefixes for variable-length fields and big-endian encoding for object-format integers. We serialize the same field values in the same way before signing or authenticating them.

| Record | Fields and fixed sizes |
|---|---|
| Credential | Version, type, user ID, 16-byte salt, Argon2id parameters, 32-byte authentication value |
| Public key | Version, type, user ID, 65-byte P-256 public key, 384-byte RSA modulus, RSA public exponent |
| Wrapped private key | Version, type, user ID, 12-byte nonce, ciphertext, 16-byte authentication tag |

We encrypt both the RSA and P-256 private material inside the wrapped private-key record. The 32-byte P-256 scalar length does not by itself specify its byte order or the complete private-record serialization.

## 7. Storage and Account Handling

| Data | Location |
|---|---|
| Password and Argon2id output | Client-side processing |
| Private-key wrapping key | Client-side only |
| Unwrapped private keys | Client-side only |
| Credential record | Server storage |
| Public-key record | Server storage and client trust handling |
| Wrapped private-key record | Server storage, retrieved by the client |
| Trusted-key pins and verification status | Private client storage managed by Person 3 |

We treat the shared directory as an attacker-controlled network. Authentication secrets must be protected during transfer. A challenge does not protect an authentication key that has already been exposed.

### Login exchange

During this login exchange, we send an HMAC response rather than the authentication value itself. The client and server exchange messages through the shared directory.

1. The client sends the username.
2. The server generates a fresh 32-byte challenge from OS cryptographic
   randomness, stores it against the pending attempt, and returns it together
   with the account's salt and Argon2id parameters.
3. The client derives the authentication value from the password and replies
   with `hmac_sha256(authentication_value, challenge)`.
4. The server recomputes the tag from its stored authentication value and the challenge, then uses `compare_tags` to check the response. It consumes the challenge on the first response, whether the check succeeds or fails. Login proceeds only if the check succeeds.

A challenge is valid for 60 seconds and for one response only. It is deleted
once used, so the same response is not accepted again for that attempt. The challenge is consumed atomically to prevent two simultaneous responses from using it. An observer sees the challenge and its HMAC response, but the authentication value is not sent by this exchange.

Expired challenges, reused challenges, wrong passwords, and unknown usernames
all produce the same authentication-failure response, with no detail
distinguishing them.

### Unknown-user handling

We aim to give the same failure response and similar processing time for unknown usernames and wrong passwords. Step 2 of the login exchange returns a salt and
Argon2id parameters before any password check, so an unknown username must
produce a response of the same shape.

For an unknown username the server derives a dummy salt as the first 16 bytes
of `hmac_sha256(server_dummy_key, username.encode("utf-8"))`, where `server_dummy_key` is a
32-byte value generated from OS cryptographic randomness once when the server
is initialised and stored server-side. The derivation is deterministic, so repeated requests for the same unknown username return the same salt. This avoids revealing unknown users through a salt that changes on every request.

The server returns the measured Argon2id settings and reads a dummy credential record from disk. It computes `hmac_sha256(dummy_authentication_value, challenge)` and compares that tag with the response using `compare_tags`. An unknown username is rejected regardless of the comparison result.

We use similar operations on both paths: read a credential record, return a salt and parameters, compute an HMAC, and compare tags. Similar operations alone do not guarantee equal timing. Wrong-password and unknown-user
attempts produce the same authentication-failure response, and neither creates
an authenticated session.

Our timing-test criterion is fixed before measurement: across 500 interleaved attempts,
the difference between the median times of the two paths must be under 5% of
the larger median. A persistent difference above that threshold fails. Passing only shows that this median-time criterion was met under the test conditions; it does not prove that account existence cannot be inferred.

Verification errors use a limited set of categories, including `Malformed object`, `Key mismatch`, `Verification failed`, and `Stale object`.

Password changes require authorization and verification of the old password. They replace authentication and wrapping values while preserving the existing RSA and P-256 key pairs. Credential and wrapped-key updates must remain consistent after interruption.


## 8. Team Responsibilities

| Person | Components provided |
|---|---|
| Person 1 | Account and session handlers; RSA key generation and RSA-PSS; HMAC and HKDF; private-key wrapping and recovery; tests for these components |
| Person 2 | SHA-256 and AEAD; shared serialization; shared-directory transport; server dispatch and storage; support for consistent account updates |
| Person 3 | P-256 key generation and key representations; public-key validation; trust and sharing integration |

Each of us is responsible for the components listed above. We use the shared interfaces when connecting our code so that the three parts work together.
