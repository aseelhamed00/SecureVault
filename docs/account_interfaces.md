# Account Interface Agreement

We use this document to keep our work on SecureVault consistent across the three of us. It brings together our agreed interfaces, data formats, cryptographic parameters, and the account behavior we have implemented and tested so far, including registration, login, sessions, private-key recovery, and password changes.

## General Conventions

- We use `bytes` for cryptographic messages, digests, tags, and derived values.
- Usernames and passwords enter the application as strings. We encode usernames as UTF-8 before passing them to cryptographic functions.
- RSA key components are Python integers in memory.
- Hexadecimal output is used for display and test vectors.
- Shared objects use a common serialization interface.
- Verification failure returns neither plaintext nor private keys.
- Cryptographic primitives retain their standard internal byte ordering.

## Cryptographic Interfaces

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
| `p256_keygen` | No arguments | `(private_key, public_key)` as 32-byte and 65-byte values | Person 3 |
| `p256_validate_public` | Public-key bytes | Boolean | Person 3 |
| `ecdh` | 32-byte private key, 65-byte public key | 32-byte shared x-coordinate | Person 3 |
| `aead_encrypt` | Key, nonce, AAD, plaintext | `(ciphertext, tag)` as separate byte values | Person 2 |
| `aead_decrypt` | Key, nonce, AAD, ciphertext, tag | Authenticated plaintext or `AuthenticationError` | Person 2 |

We call SHA-256 through `sha256(data)`. Our wrapper calls our shared `SHA_256(message)` implementation and returns a 32-byte digest. Person 2 is responsible for the shared SHA-256 module.


## RSA Key Generation and Signatures

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

We use these dictionaries in memory. The Private-Key Wrapping and Recovery section defines how we encode them inside the encrypted private-key bundle.

### Public-key serialization

We keep `n` and `e` as integers inside RSA functions. In the public-key record, we encode `n` as 384 bytes and `e = 65537` as exactly 3 bytes, both big-endian. The exponent bytes are `01 00 01`. We use `i2osp(e, 3)` when writing it and `os2ip` when converting it back to an integer. The 3-byte size belongs to our record format; it does not change the Python integer used by RSA.

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

## HMAC and HKDF

We implement these functions in `crypto/hmac_hkdf.py` using our shared `sha256` interface.

- HMAC-SHA-256 uses a 64-byte block and produces a 32-byte tag. We hash keys longer than 64 bytes before padding them.
- We compare the computed tag with the received tag using `compare_tags`, which calls `secrets.compare_digest`.
- `hkdf_extract(salt, ikm)` uses 32 zero bytes when the salt is empty or `None`.
- `hkdf_expand(prk, info, length)` requires a PRK of at least 32 bytes. Empty info is allowed; `None` is treated as empty info.
- Output length must be an integer from 0 to 8160 bytes. Boolean values are rejected. Length 0 returns empty bytes.
- `hkdf(ikm, salt, info, length)` runs Extract followed by Expand.

We test published RFC 4231 HMAC-SHA-256 vectors and RFC 5869 HKDF-SHA-256 vectors, compare results with reference libraries, and check altered tags, key lengths, purpose labels, invalid output lengths, and short PRKs. Our latest HMAC/HKDF run passed all 23 tests.

## Password Derivation

We use `derive_password_values(password, salt=None, params=None)` in `accounts.py`.

- The password is a string, encoded as UTF-8 without normalization.
- If no salt is supplied, we generate a fresh 16-byte salt using `secrets.token_bytes(16)`.
- If no parameters are supplied, we load `benchmarks/password_config.json`.
- For repeated derivation, we supply the same password, salt, and parameters.
- We derive 32 bytes using Argon2id through `argon2-cffi`, then pass this output to our HKDF-SHA-256 twice.
- We use an empty HKDF salt, `b""`, and different purpose labels.

| Derived value | Label | Length |
|---|---|---|
| Authentication value | `b"securevault:v1:auth"` | 32 bytes |
| Private-key wrapping key | `b"securevault:v1:wrap"` | 32 bytes |

The function returns this local dictionary:

| Field | Type |
|---|---|
| `salt` | 16-byte value |
| `argon2_params` | Dictionary of integer parameters |
| `auth_value` | 32-byte value |
| `wrap_key` | 32-byte value |

We keep `wrap_key` client-side. The returned dictionary is a local derivation result, not a serialized credential record. We do not include the password or raw Argon2id output in this result. Existing values are reproduced with their original salt and parameters, even if our default configuration changes.

### Selected Argon2id configuration

| Parameter | Value |
|---|---|
| `memory_cost` | 131072 KiB = 128 MiB |
| `time_cost` | 3 |
| `parallelism` | 1 |
| `hash_len` | 32 bytes |
| `version` | 19 |

Our parameter validator accepts exactly these five field names and integer values, excluding booleans. Its accepted ranges are 8192–262144 KiB for memory, 1–10 for time cost, and 1–8 for parallelism. Output length remains 32 bytes and version remains 19. These validation ranges are separate from the selected settings above.

### Password tests

We ran:

```powershell
python -m pytest tests/test_accounts.py -k derivation
```

All 8 derivation tests passed. They cover changed passwords, fresh salts, invalid inputs, reference comparison, repeated inputs, selected configuration, separate authentication and wrapping values, and two users. Our test password is `Test-only-password-123!`. Different salts produce different derivation results; identical inputs reproduce the same values.

### Password measurements

We ran:

```powershell
python -m benchmarks.passwords
```

We measured Argon2id plus both HKDF derivations, with one warm-up per candidate and five measured repetitions per candidate. We varied 64/128 MiB memory, 2/3 iterations, and 1/4 lanes. We randomized the candidate order between rounds.

| Memory (KiB) | Time cost | Parallelism | Median (seconds) |
|---|---|---|---|
| 65536 | 2 | 1 | 0.0797 |
| 65536 | 2 | 4 | 0.0338 |
| 65536 | 3 | 1 | 0.1124 |
| 65536 | 3 | 4 | 0.0471 |
| 131072 | 2 | 1 | 0.1602 |
| 131072 | 2 | 4 | 0.0662 |
| 131072 | 3 | 1 | 0.2301 |
| 131072 | 3 | 4 | 0.0870 |

We recorded these measurements on 13 September 2026 using Windows 11, AMD64, 22 logical CPUs, Python 3.13.14, and argon2-cffi 25.1.0. The reported processor identifier is `Intel64 Family 6 Model 170 Stepping 4, GenuineIntel`.

We selected 128 MiB, 3 iterations, and 1 lane because its median was closest to our 0.25-second target among the eight measured candidates. Its measured range was about 0.2252–0.2375 seconds. This is our measured derivation time on this machine, not a guaranteed runtime or a full-login measurement.

| File | Purpose |
|---|---|
| `benchmarks/password_measurements.json` | Records hardware, software, candidate parameters, repeated timings, and the reason for our selection |
| `benchmarks/password_config.json` | Stores the five selected parameters loaded by `accounts.py` |

These JSON files store measurement and configuration data, not account passwords or derived keys.

## P-256 Key Representation

We use the representations in the shared `p256.py` file:

- Private key: a 32-byte big-endian scalar, with value from 1 to the curve order minus 1.
- Public key: 65-byte uncompressed form, `0x04 || x || y`, with each coordinate encoded as 32 bytes, big-endian.
- `p256_keygen()` returns the private key first and the public key second.
- `p256_validate_public(public_key)` checks the encoding and curve point and returns a boolean.
- `ecdh(private_key, public_key)` validates its key inputs and returns the shared point's x-coordinate as 32 big-endian bytes.

## Shared Object Formats

We use the layouts in the shared `formats.py` file. Each object starts with a one-byte version and a one-byte type. The current outer-object version is 1. The encrypted inner key bundle has its own version, described in the Private-Key Wrapping and Recovery section. `pack_str(data)` writes a 4-byte big-endian byte length followed by the data; `unpack_str(buffer, offset)` returns the data and next offset. Despite the name, these functions take byte fields.

The tables below show field order after the two-byte header. `LP(field)` means a length-prefixed byte field. Fixed fields have no length prefix.

| Object | Type | Fields in order |
|---|---|---|
| `Credential` | 1 | `LP(user_id)`, salt (16), `LP(argon2_params)`, stored verifier (32) |
| `PublicKey` | 2 | `LP(user_id)`, P-256 public key (65), RSA modulus (384), RSA exponent (3) |
| `WrappedPrivateKey` | 3 | `LP(user_id)`, nonce (12), `LP(ciphertext)`, tag (16) |
| `Document` | 4 | document ID (16), `LP(owner_id)`, `LP(filename)`, `LP(mime_type)`, size (8), timestamp (8), nonce (12), `LP(ciphertext)`, tag (16) |
| `Share` | 5 | document ID (16), `LP(sender_id)`, `LP(recipient_id)`, sender fingerprint (32), recipient fingerprint (32), sequence number (8), timestamp (8), ephemeral public key (65), `LP(wrapped_document_key)`, signature (384) |

We encode size, timestamp, and sequence number as unsigned big-endian integers. Text fields are encoded as UTF-8 before serialization.

`Document.get_aad()` returns the document ID, length-prefixed owner ID, filename and MIME type, followed by size and timestamp. `Share.signed_bytes()` returns the share fields through the wrapped document key. In the current file, neither method includes the version/type header.

The format classes provide `to_bytes()` and `from_bytes()`. Our updated readers reject missing fixed bytes, truncated length-prefixed fields, wrong headers, and trailing bytes. Before writing a `WrappedPrivateKey`, we check the byte fields and require a 12-byte nonce and 16-byte tag.

`WrappedPrivateKey.get_aad()` returns `bytes([1, 3]) + pack_str(user_id)`. We use this same helper for wrapping and recovery.

### Credential parameter encoding

`derive_password_values()` returns `argon2_params` as a dictionary. In registration, `encode_argon2_params()` writes five unsigned 4-byte big-endian integers in this order:

`memory_cost`, `time_cost`, `parallelism`, `hash_len`, `version`.

The result is exactly 20 bytes. `Credential.to_bytes()` then applies `pack_str` to those bytes. `decode_argon2_params()` checks the 20-byte size, restores the dictionary, and validates the parameters.

In the current registration code, the field named `Credential.auth_value` stores `sha256(auth_value)`, a 32-byte verifier. The original HKDF authentication value stays in the local client result. We distinguish these two values even though the existing record field retains its name.


## Private-Key Wrapping and Recovery

We implement these functions in `private_keys.py`:

| Function | Inputs | Successful result |
|---|---|---|
| `serialize_bundle` | Local key-bundle dictionary | Encoded private-bundle bytes |
| `parse_bundle` | Encoded private-bundle bytes | Validated key-bundle dictionary |
| `wrap_private_keys` | `user_id`, 32-byte `wrap_key`, bundle | `WrappedPrivateKey` object |
| `unwrap_private_keys` | Expected `user_id`, 32-byte `wrap_key`, record | Recovered key-bundle dictionary |

The local bundle has exactly four fields: `rsa_private`, `rsa_public`, `p256_private`, and `p256_public`. The RSA dictionaries use the fields in the RSA Key Generation and Signatures section. P-256 uses the byte representations in the P-256 Key Representation section.

### Inner bundle format

We use `pack_str` for every field inside the encrypted bundle. The header is one byte for version 2 and one byte for type 16. The fields follow this order:

| Order | Field | Representation before `pack_str` |
|---|---|---|
| 1 | P-256 private key | Exactly 32 big-endian bytes |
| 2 | P-256 public key | Exactly 65 uncompressed bytes |
| 3 | RSA `n` | Minimal unsigned big-endian bytes, at most 384 |
| 4 | RSA `e` | Minimal unsigned big-endian bytes; `65537` is `01 00 01` |
| 5 | RSA `d` | Minimal unsigned big-endian bytes, at most 384 |
| 6 | RSA `p` | Minimal unsigned big-endian bytes, at most 192 |
| 7 | RSA `q` | Minimal unsigned big-endian bytes, at most 192 |

We reject leading zero bytes in RSA integer fields, empty fields, oversized fields, and trailing data. The complete encoded bundle is at most 1282 bytes. We reconstruct `rsa_public` from the stored `n` and `e` rather than storing those integers twice.

The length prefixes are encrypted with the bundle; only the overall ciphertext length is visible outside it. The outer public-key record still uses the fixed sizes in the Shared Object Formats section. Version 1 fixed-length private bundles are not accepted by the new parser. Existing data in that earlier format needs explicit migration; our tests generate fresh bundles.

### Bundle checks

We check that the P-256 scalar is in range, the public point is valid, and the public point equals the generator multiplied by the private scalar. For RSA, we check the component types, factor and modulus sizes, `n = p * q`, distinct factors, `e = 65537`, the private-exponent relationship, and agreement between the public and private dictionaries. These are bundle consistency checks; primality testing belongs to RSA key generation.

### Wrapping and authentication

We encrypt the complete bundle using ChaCha20-Poly1305 with the 32-byte wrapping key. Each call generates a fresh 12-byte nonce using `secrets.token_bytes`. The public function does not accept a supplied nonce. Our deterministic tests replace the random function only inside the test.

The AAD binds the outer version, type, and length-prefixed user ID using `WrappedPrivateKey.get_aad()`. The nonce, ciphertext, and 16-byte tag are stored in the outer record. Our AEAD interface checks key and nonce lengths and compares the received tag using `secrets.compare_digest` before decrypting. `aead_decrypt()` raises `AuthenticationError`, which is a subclass of `ValueError`; the account-side recovery code converts authentication failures to the same generic `Verification failed` result.

Recovery accepts a `WrappedPrivateKey` object or its serialized bytes. We supply the expected user ID independently and check it against the record. We authenticate the ciphertext before calling `parse_bundle`, and return the keys only after the recovered bundle also passes validation. Wrong identities, failed authentication, and malformed bundles raise exceptions without returning private material.

A transport retry can resend the completed record unchanged. We do not deliberately reuse a key/nonce pair for another encryption. Random nonces give probabilistic uniqueness, not a persistent guarantee against every repetition; the full key lifecycle must preserve this requirement when we connect later account operations.

## Registration and Local Storage

| Function | Inputs | Successful result |
|---|---|---|
| `register` | `user_id`, password, optional parameters | Local account dictionary |
| `check_registration_records` | Dictionary of three serialized records | Validated user ID |
| `handle_registration` | Store, serialized records | Stored user ID |
| `account_exists` | Store, user ID | Boolean based on a complete stored account |
| `register_account` | Store, user ID, password, optional parameters | Local account dictionary after storage |

`register()` runs on the client. We encode a non-empty string ID as UTF-8, or accept a non-empty byte ID. We derive password values with a fresh salt, generate both key pairs, wrap the private bundle, and build the credential and public-key records.

The local return value contains `user_id`, `records`, `bundle`, `wrap_key`, `auth_value`, and `fingerprint`. Only the `records` dictionary is passed to the server handler:

| Record name | Content |
|---|---|
| `credential` | Serialized `Credential`, containing salt, parameters, and verifier |
| `public_key` | Serialized `PublicKey`, containing both public keys |
| `wrapped_private_key` | Serialized authenticated encrypted key bundle |

We keep the full return value client-side. We do not pass its plaintext bundle, wrapping key, or original authentication value to the storage handler. The password and raw Argon2id output are not included in the return value.

`public_key_fingerprint()` computes SHA-256 over the serialized public-key record, including the user ID and both public keys. We use this function to compute the fingerprint; TOFU verification is a separate part of our key-trust work.

The server handler checks that all three records are present, parse correctly, and carry the same non-empty user ID. It also validates Argon2 parameters, the 3072-bit RSA modulus size, exponent 65537, the P-256 public point, and a non-empty wrapped ciphertext. Authentication and private-bundle validation occur during client recovery; the server has no wrapping key.

### Atomic storage interface

We require these operations from the storage adapter:

| Method | Required behavior |
|---|---|
| `create_account(user_id, records)` | Save all three records together and reject duplicate IDs atomically |
| `get_account(user_id)` | Return the complete three-record dictionary, or `None` for an absent account |
| `get(kind, user_id)` | Return one record from a complete account |

Our current `account_store.AccountStore` uses a local SQLite database through Python's standard library. It begins a write transaction, checks for an existing ID, writes the three records, and commits them together. Reads do not treat a lone credential record as an account. An incomplete stored record set raises an error.

An interruption before commit leaves no published account. An interruption after commit leaves a complete account, even if the response was lost; retrying the same ID is rejected as a duplicate. We do not delete an already committed account to handle a lost response. The transaction also prevents concurrent registrations from both taking the same ID.

This adapter is for local integration. We have not connected it to our shared-directory transport yet. The database belongs to the server's local storage, not to the directory used to exchange network messages. `register_account()` runs both sides locally for tests and demonstrations.

## Login and Unknown-Account Handling

We use a challenge-response login flow. The account functions are kept separate from the transport so the shared-directory transport can call the same handlers without changing the account logic.

A login starts with `begin_login()`. The challenge returned to the client contains the same type of fields whether the username exists or not:

| Field | Size / meaning |
|---|---|
| `user_id` | UTF-8 user ID |
| `challenge_id` | 16 random bytes |
| `challenge` | 32 random bytes |
| `salt` | 16 bytes |
| `argon2_params` | 20-byte encoded parameter set |
| `expires_at` | Challenge expiry time |

Challenges are valid for 30 seconds. The server keeps their state locally and consumes a challenge on the first finish attempt, whether that attempt succeeds or fails. Reusing the same challenge therefore fails.

For an existing user, we return the stored salt and Argon2id parameters. For an unknown user, we return a dummy salt with the same format and the normal Argon2id parameters. The dummy salt is stable for the same unknown username and is derived from a server-side random secret. This keeps the external path for an unknown username close to the path for a real account.

The client derives the password values from the challenge salt and parameters. It keeps the wrapping key locally and builds the login response from the authentication side only:

```text
login_key = SHA-256(auth_value)
response = HMAC-SHA-256(login_key, login_transcript)
```

The deterministic login transcript contains the user ID, challenge ID, random challenge, salt, Argon2id parameters, and expiry time. The network response contains the challenge ID and HMAC response, not the password, wrapping key, raw Argon2id result, or private keys.

`finish_login()` reconstructs the original transcript from the stored challenge state and verifies the response. Known accounts use the stored credential verifier. Unknown accounts follow the same response-processing path with a dummy key.

Wrong passwords, unknown usernames, altered responses, expired challenges, and replayed challenges use the same external failure:

```text
Authentication failed
```

After a valid response, the server creates a session for the authenticated user and returns the public-key record and wrapped-private-key record needed by the client. The client unwraps the private bundle using the wrapping key it derived locally. We do not return private material if the server-side authentication check fails.

The recovered P-256 and RSA public keys are checked against the stored `PublicKey` record before login completes. A changed public-key record, wrapped-private-key record, user ID, nonce, ciphertext, or tag causes recovery to fail.

### Login timing behavior

We test wrong-password and unknown-user attempts repeatedly in interleaved order. The two cases use the same external failure message, and our timing test compares their sample medians using this tolerance:

```text
max(15 ms, 25% of the larger median)
```

Passing this test is evidence that the two paths are not persistently distinguishable in our test environment. It is not a claim that timing leakage is impossible on every machine.

### Login limitation

The stored credential verifier is also the value the server uses to verify the login HMAC. This means a stolen credential database does not reveal the password or the private-key wrapping key, but possession of the stored verifier can be useful for protocol impersonation. We keep this as an explicit limitation rather than treating the verifier as equivalent to the password.

## Session Handling

A successful login creates a server-side session bound to the authenticated account.

Each session stores:

| Field | Meaning |
|---|---|
| `session_id` | 16 random bytes |
| `user_id` | Identity fixed by the authenticated login |
| `expires_at` | Expiration time |
| `invalidated` | Server-side invalidation state |

The current session lifetime is 15 minutes. Expired and invalidated sessions are rejected.

For each successful login, both sides derive a request-authentication key:

```text
session_key = HKDF-SHA-256(
    IKM = login_key,
    salt = session_id,
    info = b"securevault:v1:session-key",
    length = 32
)
```

The client derives this from the login key it already has. The server derives the same value from the stored credential verifier. We do not store a separate session MAC key in the database.

Authenticated requests contain:

| Field | Size / format |
|---|---|
| `session_id` | 16 bytes |
| `request_id` | 16 fresh random bytes |
| `user_id` | Claimed UTF-8 identity |
| `operation` | Byte string |
| `payload` | Byte string |
| `tag` | 32-byte HMAC-SHA-256 tag |

The HMAC covers the session ID, request ID, user ID, operation, and payload in one deterministic transcript.

The identity carried inside the request does not decide who the request belongs to. The authenticated identity comes from the server-side session record. If a request tries to name another user, it is rejected even if the sender has a valid session.

After a request passes the session, identity, and HMAC checks, the server records its `request_id`. Reusing the same `(session_id, request_id)` is rejected as a replay. These replay records are kept in SQLite, so reopening the server storage does not make an already accepted request valid again.

A request that fails HMAC or identity verification does not consume its request ID.

`validate_session()` checks the stored session state. Normal authenticated operations use `validate_session_request()` so possession of a session ID alone is not enough. `invalidate_session()` marks a session unusable, and the same generic external failure is used for missing, altered, expired, invalidated, identity-mismatched, unauthenticated, or replayed requests:

```text
Authentication failed
```

## Password Changes and Recovery

Changing a password does not change the user's RSA or P-256 identity keys. We recover the existing private-key bundle with the old password, derive new password-dependent values, and wrap the same bundle again under the new wrapping key.

### Password-change context

The client obtains the current account material through an authenticated session request. The returned context contains:

| Field | Meaning |
|---|---|
| `user_id` | Identity bound to the session |
| `salt` | Current 16-byte Argon2id salt |
| `argon2_params` | Current encoded Argon2id parameters |
| `public_key` | Current serialized public-key record |
| `wrapped_private_key` | Current serialized encrypted private-key bundle |

We do not include the stored credential verifier in this context.

The operation name used for this request is:

```text
b"password-change-context"
```

### Client-side change

`prepare_password_change()` uses the old password with the current salt and parameters. The old wrapping key must successfully recover the current private-key bundle before the change continues. We also check that the recovered RSA and P-256 public keys still match the current public-key record.

The new password is derived with a fresh 16-byte salt. We generate a new authentication value and a new wrapping key, then re-encrypt the same private-key bundle. A new `Credential` record and `WrappedPrivateKey` record are created, while the `PublicKey` record stays unchanged.

The client also creates an old-password proof:

```text
proof = HMAC-SHA-256(old_login_key, proof_transcript)
```

The proof binds the session, user ID, current salt and parameters, the hashes of the current public and wrapped-private-key records, and the hash of the proposed new credential/wrapped-key body.

The normal session HMAC protects the complete password-change request as well. The password, old wrapping key, new wrapping key, and unwrapped private keys never appear in the transport payload.

### Atomic server update

`handle_password_change()` first validates the authenticated session request and then verifies the old-password proof using the current credential state.

The storage update is performed by `AccountStore.update_password_records()` in one SQLite transaction. The transaction:

- checks that the current credential and wrapped-private-key records are still the exact records on which the change was prepared;
- replaces the credential record;
- replaces the wrapped-private-key record;
- invalidates all existing sessions for the user;
- commits the complete change together.

The public-key record is not modified. The RSA and P-256 identity keys and the public-key fingerprint therefore remain the same after the password changes.

A stale password-change request cannot overwrite a newer password state because the expected current records must still match.

### Session policy after a password change

A successful password change invalidates every existing session for that account, including the session that performed the change. The user must log in again with the new password.

If the old password is wrong, the existing private-key bundle cannot be recovered and the change does not proceed. The stored account state and current sessions stay unchanged.

### Interrupted updates

The credential replacement, wrapped-private-key replacement, and session invalidation are one transaction.

If an interruption happens before commit, the complete old password state remains. If commit has already completed, the complete new state remains. We do not accept a mixed state such as a new credential with the old wrapped private-key record.

If a request ID was consumed but the password transaction did not commit, the client creates a new authenticated request with a fresh request ID after checking which password state is active. If the commit completed but the response was lost, the new password is already active and the old sessions are already invalidated.

## Current Test Results

Our account test file now covers password derivation, registration, login, unknown-account handling, timing behavior, sessions, replay protection, and password changes.

After the password-change work was added, we ran:

```powershell
python -m pytest tests/test_accounts.py
```

The complete run passed all 55 tests on Windows with Python 3.13.14.

We also ran the focused account checks after the session and password-change updates:

```powershell
python -m pytest tests/test_accounts.py -k session
python -m pytest tests/test_accounts.py -k login
python -m pytest tests/test_accounts.py -k timing
```

The latest runs passed 16 session tests, 13 login-related tests, and the timing test. The full 55-test run also includes the password-change cases together with the earlier derivation and registration tests.

The account tests cover correct and incorrect passwords, unknown usernames, altered and replayed login challenges, session expiry and invalidation, identity changes inside authenticated requests, captured-request replay, fresh salts, unchanged RSA/P-256 identity keys after password changes, all-session invalidation after a successful change, and interrupted account updates.

The private-key tests remain responsible for serialization, key consistency, correct recovery, modified nonce/ciphertext/tag handling, wrong wrapping keys, changed identities, malformed bundles, and the rule that private-bundle parsing only happens after successful authentication.

These results cover our current local account/storage implementation. Final shared-directory transport and application integration are still separate work.

## Libraries and Team Responsibilities

We keep implementation ownership separate even when one part depends on another member's interface.

Our shared SHA-256 implementation is owned by Person 2. RSA key generation, RSA-PSS, HMAC-SHA-256, and HKDF-SHA-256 are our own implementations on the Person 1 side. We use `argon2-cffi` for Argon2id. Reference cryptographic libraries are used in tests for comparison. Person 2 owns ChaCha20, Poly1305, ChaCha20-Poly1305, the shared object formats, and the application transport/storage integration. Person 3 owns the P-256 arithmetic, key generation, validation, ECDH, trust, sharing, and freshness side.

Standard Python modules are used for randomness, paths, JSON, timing, statistics, machine information, and SQLite storage. `pytest` is used for the test suite.

| Person | Current work covered here |
|---|---|
| Person 1 | RSA key generation and PSS; HMAC and HKDF; password derivation and measurements; private-key wrapping and recovery; registration; login and unknown-account handling; session handling and replay protection; password changes; local account storage and related tests |
| Person 2 | Shared SHA-256; ChaCha20/Poly1305/AEAD; shared object formats; document/infrastructure work; final transport and server/client integration |
| Person 3 | P-256 key generation and validation; ECDH; public-key trust; sharing and freshness work |

The account code uses Person 2's shared formats and AEAD and Person 3's P-256 interfaces, but those implementations remain owned by their assigned members. We keep the agreed byte sizes, function arguments, labels, and record layouts consistent across the three parts.

## Current Account Boundary

At this point, the account side covers password derivation, RSA and P-256 account key creation, protected private-key storage, atomic registration, login with unknown-account handling, session creation and validation, session expiry and invalidation, request authentication and replay rejection, and consistent password changes with atomic recovery behavior.

The next account work is final application integration with Person 2's real shared-directory transport and server/client dispatch. Sharing integration then connects the account/signature interfaces to Person 3's sharing flow.
