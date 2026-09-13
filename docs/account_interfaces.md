# Account Interface Agreement

We use this document to keep our three parts of SecureVault consistent. It records the interfaces and formats we have shared so far, including our password-derivation measurements from step 7.

## 1. General Conventions

- We use `bytes` for cryptographic messages, digests, tags, and derived values.
- Usernames and passwords enter the application as strings. We encode usernames as UTF-8 before passing them to cryptographic functions.
- RSA key components are Python integers in memory.
- Hexadecimal output is used for display and test vectors.
- Shared objects use a common serialization interface.
- Verification failure returns neither plaintext nor private keys.
- Cryptographic primitives retain their standard internal byte ordering.

## 2. Cryptographic Interfaces

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

We call SHA-256 through `sha256(data)`. Our wrapper calls our shared `SHA_256(message)` implementation and returns a 32-byte digest. Person 2 is responsible for the shared SHA-256 module.


## 3. RSA Key Generation and Signatures

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

## 4. HMAC and HKDF


We implement these functions in `crypto/hmac_hkdf.py` using our shared `sha256` interface.

- HMAC-SHA-256 uses a 64-byte block and produces a 32-byte tag. We hash keys longer than 64 bytes before padding them.
- We compare the computed tag with the received tag using `compare_tags`, which calls `secrets.compare_digest`.
- `hkdf_extract(salt, ikm)` uses 32 zero bytes when the salt is empty or `None`.
- `hkdf_expand(prk, info, length)` requires a PRK of at least 32 bytes. Empty info is allowed; `None` is treated as empty info.
- Output length must be an integer from 0 to 8160 bytes. Boolean values are rejected. Length 0 returns empty bytes.
- `hkdf(ikm, salt, info, length)` runs Extract followed by Expand.

We test published RFC 4231 HMAC-SHA-256 vectors and RFC 5869 HKDF-SHA-256 vectors, compare results with reference libraries, and check altered tags, key lengths, purpose labels, invalid output lengths, and short PRKs.

## 5. Password Derivation

Responsible team member: Person 1

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

## 6. P-256 Key Representation

Responsible team member: Person 3

We use the representations in the shared `p256.py` file:

- Private key: a 32-byte big-endian scalar, with value from 1 to the curve order minus 1.
- Public key: 65-byte uncompressed form, `0x04 || x || y`, with each coordinate encoded as 32 bytes, big-endian.
- `p256_keygen()` returns the private key first and the public key second.
- `p256_validate_public(public_key)` checks the encoding and curve point and returns a boolean.
- `ecdh(private_key, public_key)` validates its key inputs and returns the shared point's x-coordinate as 32 big-endian bytes.

## 7. Shared Object Formats

Responsible team member: Person 2

We use the layouts in the shared `formats.py` file. Each object starts with a one-byte version and a one-byte type. The current version is 1. `pack_str(data)` writes a 4-byte big-endian byte length followed by the data; `unpack_str(buffer, offset)` returns the data and next offset. Despite the name, these functions take byte fields.

The tables below show field order after the two-byte header. `LP(field)` means a length-prefixed byte field. Fixed fields have no length prefix.

| Object | Type | Fields in order |
|---|---|---|
| `Credential` | 1 | `LP(user_id)`, salt (16), `LP(argon2_params)`, auth value (32) |
| `PublicKey` | 2 | `LP(user_id)`, P-256 public key (65), RSA modulus (384), RSA exponent (3) |
| `WrappedPrivateKey` | 3 | `LP(user_id)`, nonce (12), `LP(ciphertext)`, tag (16) |
| `Document` | 4 | document ID (16), `LP(owner_id)`, `LP(filename)`, `LP(mime_type)`, size (8), timestamp (8), nonce (12), `LP(ciphertext)`, tag (16) |
| `Share` | 5 | document ID (16), `LP(sender_id)`, `LP(recipient_id)`, sender fingerprint (32), recipient fingerprint (32), sequence number (8), timestamp (8), ephemeral public key (65), `LP(wrapped_document_key)`, signature (384) |

We encode size, timestamp, and sequence number as unsigned big-endian integers. Text fields are encoded as UTF-8 before serialization.

`Document.get_aad()` returns the document ID, length-prefixed owner ID, filename and MIME type, followed by size and timestamp. `Share.signed_bytes()` returns the share fields through the wrapped document key. In the current file, neither method includes the version/type header.

The format classes provide `to_bytes()` and `from_bytes()`. These layouts describe the shared file; they do not establish that account, document, or sharing flows have been integrated and tested. The `Credential` class receives `argon2_params` as bytes, while `derive_password_values()` returns them as a dictionary. We do not define a new encoding for that dictionary in this document.

## 8. Libraries and Current Team Work

We wrote our shared SHA-256 implementation to keep our work consistent. Our RSA, PSS, HMAC, and HKDF code uses our own implementations. We use `argon2-cffi` for Argon2id. Reference cryptographic libraries are used in tests to compare results with ours.

Standard Python modules used for randomness, paths, JSON, timing, statistics, and machine information support the implementation and measurements. They do not replace our cryptographic functions. We use `pytest` to run the tests.

| Person | Current work covered here |
|---|---|
| Person 1 | RSA key generation and PSS; HMAC and HKDF; password derivation; associated tests and Argon2id measurements |
| Person 2 | Our shared SHA-256 interface and the supplied object-format definitions |
| Person 3 | Supplied P-256 key generation, public-key validation, and ECDH interfaces |

We keep the byte sizes, function arguments, and labels consistent when connecting these parts.
