# Account Interface Agreement

We use this document to keep our work on SecureVault consistent across the three of us. It brings together our agreed interfaces, data formats, cryptographic parameters, and the behavior we have implemented and tested for password derivation, private-key recovery, and local registration.

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
| `chacha20_poly1305_encrypt` | Key, nonce, plaintext, AAD | `(ciphertext, tag)` as separate byte values | Person 2 |
| `chacha20_poly1305_decrypt` | Key, nonce, ciphertext, tag, AAD | Authenticated plaintext or `ValueError` | Person 2 |

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

The AAD binds the outer version, type, and length-prefixed user ID using `WrappedPrivateKey.get_aad()`. The nonce, ciphertext, and 16-byte tag are stored in the outer record. Our AEAD interface checks key and nonce lengths and compares the received tag using `secrets.compare_digest` before decrypting.

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

### Current authentication compatibility

We preserve `credential_verifier(auth_value) = sha256(auth_value)` from the current registration code. Storing this hash does not by itself provide replay protection or protect registration messages in transit. A server holding this verifier cannot directly check an HMAC keyed by the original authentication value. We have not connected this representation to a final login or protected registration-transfer protocol.

## Current Test Results

We ran the corrected private-key and account tests together on Windows:

```powershell
python -m pytest tests/test_private_keys.py tests/test_accounts.py -v --tb=short
```

The run passed 55 tests and 52 subtests in 69.04 seconds. It includes our eight password-derivation tests.

Our private-key tests cover serialization, key consistency, correct recovery, signing after recovery, changed nonce/ciphertext/tag, wrong wrapping keys, changed identities, malformed records, and rejection before private-bundle parsing when authentication fails. They also reject an invalid inner bundle with a valid AEAD tag.

Our registration tests cover two users with the same password, distinct records, duplicate IDs, malformed public keys and records, parameter validation, recovery of stored wrapped keys, and absence of the tested plaintext secrets from serialized records and the local database. We test exceptions after each write, abrupt process exit before and after commit, reopening storage, retry, and concurrent duplicate registrations.

These results apply to the current local adapter and temporary Poly1305 implementation. They do not establish shared-directory transport security or physical disk-failure behavior.

## Libraries and Team Responsibilities

We wrote our shared SHA-256 implementation to keep our work consistent. Our RSA, PSS, HMAC, and HKDF code uses our own implementations. We use `argon2-cffi` for Argon2id. Reference cryptographic libraries are used in tests to compare results with ours. Our current Poly1305 module is also a temporary wrapper around `cryptography` for integration testing; we are using it until our team implementation is ready. We will replace it and rerun the tests before treating that primitive as complete.

Standard Python modules used for randomness, paths, JSON, timing, statistics, machine information, and SQLite storage support the implementation and measurements. They do not replace our cryptographic functions. We use `pytest` to run the tests.

| Person | Current work covered here |
|---|---|
| Person 1 | RSA key generation and PSS; HMAC and HKDF; password derivation; private-key wrapping and recovery; local registration and atomic storage adapter; associated tests and measurements |
| Person 2 | Shared SHA-256, supplied ChaCha20/AEAD interfaces, and object-format definitions |
| Person 3 | Supplied P-256 key generation, public-key validation, and ECDH interfaces |

We keep the byte sizes, function arguments, and labels consistent when connecting these parts.
