from secrets import compare_digest
from .chacha20 import chacha20_block, chacha20_encrypt
from .poly1305 import poly1305


class AuthenticationError(ValueError):
    pass


def _check_key_nonce(key: bytes, nonce: bytes):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("AEAD nonce must be 12 bytes")


def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - len(data) % 16)


def _poly1305_key(key: bytes, nonce: bytes) -> bytes:
    return chacha20_block(key, nonce, 0)[:32]


def _mac_input(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        _pad16(aad)
        + _pad16(ciphertext)
        + len(aad).to_bytes(8, 'little')
        + len(ciphertext).to_bytes(8, 'little')
    )


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes):
    _check_key_nonce(key, nonce)

    poly_key = _poly1305_key(key, nonce)
    ciphertext = chacha20_encrypt(key, nonce, plaintext, counter=1)
    tag = poly1305(poly_key, _mac_input(aad, ciphertext))
    return ciphertext, tag


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:

    _check_key_nonce(key, nonce)

    if not isinstance(tag, bytes) or len(tag) != 16:
        raise AuthenticationError("AEAD tag must be 16 bytes -- object is malformed")

    poly_key = _poly1305_key(key, nonce)
    expected_tag = poly1305(poly_key, _mac_input(aad, ciphertext))

    if not compare_digest(tag, expected_tag):
        raise AuthenticationError("AEAD tag mismatch -- ciphertext or metadata was altered")

    return chacha20_encrypt(key, nonce, ciphertext, counter=1)
