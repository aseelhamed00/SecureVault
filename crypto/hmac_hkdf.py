import secrets

from crypto.sha256 import sha256


BLOCK_SIZE = 64
HASH_LEN = 32
HKDF_MAX_LEN = 255 * HASH_LEN


def hmac_sha256(key, data):
    key = bytes(key)

    # If the key is too long, hash it first
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    # Make the key 64 bytes
    key = key + b"\x00" * (BLOCK_SIZE - len(key))

    inner = bytes(byte ^ 0x36 for byte in key)
    outer = bytes(byte ^ 0x5C for byte in key)

    inner_hash = sha256(inner + bytes(data))

    return sha256(outer + inner_hash)


def compare_tags(left, right):
    return secrets.compare_digest(bytes(left), bytes(right))


def hkdf_extract(salt, ikm):
    # HKDF uses a zero salt if no salt is given
    if not salt:
        salt = b"\x00" * HASH_LEN

    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    if len(prk) < HASH_LEN:
        raise ValueError("prk must be at least 32 bytes")
    
    if not isinstance(length, int) or isinstance(length, bool):
        raise ValueError("length must be a non-negative integer")

    if length < 0:
        raise ValueError("length must be a non-negative integer")

    if length > HKDF_MAX_LEN:
        raise ValueError("requested length exceeds the HKDF-SHA-256 limit")

    if info is None:
        info = b""

    info = bytes(info)

    result = b""
    previous = b""
    counter = 1

    while len(result) < length:
        previous = hmac_sha256(
            prk,
            previous + info + bytes([counter])
        )

        result += previous
        counter += 1

    return result[:length]


def hkdf(ikm, salt, info, length):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)