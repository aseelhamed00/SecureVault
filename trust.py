from crypto.sha256 import sha256
from crypto.p256 import p256_validate_public


def _add_length(data):
    return len(data).to_bytes(4,"big") + data

def _build_key_data(user_id, p256_public_key, rsa_public_key, rsa_public_exponent):
    if not isinstance(user_id, str):
        raise TypeError("User ID must be a string")

    if not isinstance(p256_public_key, bytes):
        raise TypeError("P256 public key must be bytes")

    if len(p256_public_key) != 65:
        raise ValueError("P256 public key must be 65 bytes")

    if not p256_validate_public(p256_public_key):
        raise ValueError("Invalid P256 public key")

    if not isinstance(rsa_public_key, int):
        raise TypeError("RSA public key must be an integer")

    if rsa_public_key < 0:
        raise ValueError("Invalid RSA public key")

    if not isinstance(rsa_public_exponent, int):
        raise TypeError("RSA exponent must be an integer")

    if rsa_public_exponent <= 0:
        raise ValueError("Invalid RSA exponent")

    user_bytes = user_id.encode("utf-8")
    rsa_bytes = rsa_public_key.to_bytes(384, "big")
    exponent_bytes = rsa_public_exponent.to_bytes(
        (rsa_public_exponent.bit_length() + 7) // 8,
        "big"
    )

    data = b""
    data += _add_length(user_bytes)
    data += _add_length(p256_public_key)
    data += _add_length(rsa_bytes)
    data += _add_length(exponent_bytes)

    return data


def fingerprint_public_key(user_id, p256_public_key, rsa_public_key, rsa_public_exponent):
    
    data = _build_key_data(
        user_id,
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    return sha256(data)


def fingerprint_hex(user_id, p256_public_key,rsa_public_key, rsa_public_exponent):

    fingerprint = fingerprint_public_key(
        user_id,
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    return fingerprint.hex()


def trust_first_key(trusted_keys, user_id, p256_public_key, rsa_public_key, rsa_public_exponent):

    if user_id in trusted_keys:
        return False

    fingerprint = fingerprint_public_key(
        user_id,
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    trusted_keys[user_id] = {
        "p256_public_key": p256_public_key,
        "rsa_public_key": rsa_public_key,
        "rsa_public_exponent": rsa_public_exponent,
        "fingerprint": fingerprint,
        "verified": False
    }

    return True


def check_trusted_key(trusted_keys, user_id, p256_public_key,rsa_public_key, rsa_public_exponent):

    if user_id not in trusted_keys:
        return False

    fingerprint = fingerprint_public_key(
        user_id,
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    return fingerprint == trusted_keys[user_id]["fingerprint"]


def is_key_verified(trusted_keys, user_id):
    if user_id not in trusted_keys:
        return False

    return trusted_keys[user_id]["verified"]


def mark_key_verified(trusted_keys, user_id):
    if user_id not in trusted_keys:
        return False

    trusted_keys[user_id]["verified"] = True
    return True


def get_fingerprint(trusted_keys, user_id):
    if user_id not in trusted_keys:
        return None

    return trusted_keys[user_id]["fingerprint"]


def remove_trusted_key(trusted_keys, user_id):
    if user_id not in trusted_keys:
        return False

    del trusted_keys[user_id]
    return True