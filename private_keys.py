import math
import secrets

from crypto.aead import aead_decrypt, aead_encrypt
from crypto.formats import WrappedPrivateKey, check_end, pack_str, unpack_str
from crypto.p256 import N as P256_ORDER
from crypto.p256 import G, p256_validate_public, scalar_mult
from crypto.rsa_pss import i2osp, os2ip

BUNDLE_VERSION = 2
BUNDLE_TYPE = 16

WRAP_KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

P256_PRIVATE_LEN = 32
P256_PUBLIC_LEN = 65
RSA_BITS = 3072
RSA_MODULUS_LEN = 384
RSA_EXPONENT_LEN = 3
RSA_PRIME_LEN = 192


BUNDLE_MAX_LEN = 1282

BUNDLE_FIELDS = {"rsa_private", "rsa_public", "p256_private", "p256_public"}
RSA_PRIVATE_FIELDS = {"n", "e", "d", "p", "q"}


def encode_user_id(user_id):
    if isinstance(user_id, str):
        user_id = user_id.encode("utf-8")
    if not isinstance(user_id, bytes) or len(user_id) == 0:
        raise ValueError("user_id must be a non-empty string or byte string")
    return user_id


def check_wrap_key(wrap_key):
    if not isinstance(wrap_key, bytes) or len(wrap_key) != WRAP_KEY_LEN:
        raise ValueError("wrap_key must contain exactly 32 bytes")


def validate_bundle(bundle):
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        raise ValueError("Invalid key bundle fields")

    private_scalar = bundle["p256_private"]
    if not isinstance(private_scalar, bytes) or len(private_scalar) != P256_PRIVATE_LEN:
        raise ValueError("P-256 private key must contain exactly 32 bytes")

    scalar = os2ip(private_scalar)
    if scalar < 1 or scalar >= P256_ORDER:
        raise ValueError("P-256 private key is out of range")

    if not p256_validate_public(bundle["p256_public"]):
        raise ValueError("P-256 public key is not a valid curve point")

    point = scalar_mult(scalar, G)
    expected_public = b"\x04" + i2osp(point[0], 32) + i2osp(point[1], 32)
    if bundle["p256_public"] != expected_public:
        raise ValueError("P-256 public key does not match the private key")

    rsa_private = bundle["rsa_private"]
    rsa_public = bundle["rsa_public"]

    if not isinstance(rsa_private, dict) or set(rsa_private) != RSA_PRIVATE_FIELDS:
        raise ValueError("Invalid RSA private key fields")
    if not isinstance(rsa_public, dict) or set(rsa_public) != {"n", "e"}:
        raise ValueError("Invalid RSA public key fields")

    for value in list(rsa_private.values()) + list(rsa_public.values()):
        if type(value) is not int or value < 1:
            raise ValueError("RSA components must be positive integers")

    n = rsa_private["n"]
    e = rsa_private["e"]
    d = rsa_private["d"]
    p = rsa_private["p"]
    q = rsa_private["q"]

    if p == q:
        raise ValueError("RSA factors must differ")
    if p.bit_length() != RSA_BITS // 2 or q.bit_length() != RSA_BITS // 2:
        raise ValueError("RSA factors must be 1536 bits each")
    if n != p * q or n.bit_length() != RSA_BITS:
        raise ValueError("RSA modulus does not match its factors")
    if e != 65537:
        raise ValueError("RSA public exponent must be 65537")
    if d >= n:
        raise ValueError("RSA private exponent is out of range")
    if (e * d) % math.lcm(p - 1, q - 1) != 1:
        raise ValueError("RSA private exponent does not match the public exponent")
    if rsa_public["n"] != n or rsa_public["e"] != e:
        raise ValueError("RSA public key does not match the private key")


def serialize_bundle(bundle):
    validate_bundle(bundle)
    private = bundle["rsa_private"]
    fields = [bundle["p256_private"], bundle["p256_public"]]
    for name in ("n", "e", "d", "p", "q"):
        value = private[name]
        fields.append(i2osp(value, (value.bit_length() + 7) // 8))
    return bytes([BUNDLE_VERSION, BUNDLE_TYPE]) + b"".join(pack_str(field) for field in fields)


def parse_bundle(data):
    if not isinstance(data, bytes) or not 2 <= len(data) <= BUNDLE_MAX_LEN:
        raise ValueError("Malformed object")
    if data[:2] != bytes([BUNDLE_VERSION, BUNDLE_TYPE]):
        raise ValueError("Malformed object")
    offset = 2
    fields = []
    limits = (32, 65, 384, 3, 384, 192, 192)
    for limit in limits:
        field, offset = unpack_str(data, offset)
        if not field or len(field) > limit:
            raise ValueError("Malformed object")
        fields.append(field)
    check_end(data, offset)
    for field in fields[2:]:
        if field[0] == 0:
            raise ValueError("Non-canonical RSA integer")
    n, e, d, p, q = map(os2ip, fields[2:])
    bundle = {
        "p256_private": fields[0], "p256_public": fields[1],
        "rsa_private": {"n": n, "e": e, "d": d, "p": p, "q": q},
        "rsa_public": {"n": n, "e": e},
    }
    try:
        validate_bundle(bundle)
    except ValueError:
        raise ValueError("Malformed object") from None
    return bundle


def wrapped_aad(user_id):
   
    return WrappedPrivateKey(user_id, bytes(NONCE_LEN), b"", b"").get_aad()


def wrap_private_keys(user_id, wrap_key, bundle):
    user_id = encode_user_id(user_id)
    check_wrap_key(wrap_key)

    nonce = secrets.token_bytes(NONCE_LEN)

    plaintext = serialize_bundle(bundle)
    ciphertext, tag = aead_encrypt(
        wrap_key, nonce, wrapped_aad(user_id), plaintext
    )

    return WrappedPrivateKey(user_id, nonce, ciphertext, tag)


def unwrap_private_keys(user_id, wrap_key, record):
    user_id = encode_user_id(user_id)
    check_wrap_key(wrap_key)

    if isinstance(record, (bytes, bytearray)):
        record = WrappedPrivateKey.from_bytes(bytes(record))
    if not isinstance(record, WrappedPrivateKey):
        raise TypeError("record must be a WrappedPrivateKey or its serialized bytes")

    if (not isinstance(record.nonce, bytes) or len(record.nonce) != NONCE_LEN
            or not isinstance(record.tag, bytes) or len(record.tag) != TAG_LEN
            or not isinstance(record.ciphertext, bytes)):
        raise ValueError("Malformed object")

    if len(record.ciphertext) > BUNDLE_MAX_LEN:
        raise ValueError("Malformed object")

   
    if record.user_id != user_id:
        raise ValueError("Key mismatch")

    try:
        plaintext = aead_decrypt(
            wrap_key,
            record.nonce,
            wrapped_aad(record.user_id),
            record.ciphertext,
            record.tag,
        )
    except ValueError:
        
        raise ValueError("Verification failed") from None

    return parse_bundle(plaintext)