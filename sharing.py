import secrets

from crypto.p256 import p256_keygen, p256_validate_public, ecdh
from crypto.aead import aead_encrypt, aead_decrypt
from crypto.formats import Share, pack_str
from person1_interfaces import hkdf, pss_sign, pss_verify
from trust import (
    fingerprint_public_key,
    check_trusted_key,
    get_fingerprint
)
from freshness import check_freshness


SHARE_INFO = b"securevault:v1:share-wrap"


def make_wrap_aad(
    document_id,
    sender_id,
    recipient_id,
    sender_fingerprint,
    recipient_fingerprint,
    sequence_number,
    timestamp,
    ephemeral_public_key
):
    return (
        document_id
        + pack_str(sender_id)
        + pack_str(recipient_id)
        + sender_fingerprint
        + recipient_fingerprint
        + sequence_number.to_bytes(8, "big")
        + timestamp.to_bytes(8, "big")
        + ephemeral_public_key
    )


def create_share(
    document_id,
    sender_id,
    recipient_id,
    document_key,
    sender_p256_public,
    recipient_p256_public,
    sender_rsa_private,
    sender_rsa_public,
    recipient_rsa_public,
    sequence_number,
    timestamp
):
    if not isinstance(document_id, bytes) or len(document_id) != 16:
        raise ValueError("document_id must be 16 bytes")

    if not isinstance(sender_id, bytes):
        raise ValueError("sender_id must be bytes")

    if not isinstance(recipient_id, bytes):
        raise ValueError("recipient_id must be bytes")

    if not isinstance(document_key, bytes) or len(document_key) != 32:
        raise ValueError("document_key must be 32 bytes")

    if not p256_validate_public(sender_p256_public):
        raise ValueError("Invalid sender public key")

    if not p256_validate_public(recipient_p256_public):
        raise ValueError("Invalid recipient public key")

    sender_fingerprint = fingerprint_public_key(
        sender_id.decode("utf-8"),
        sender_p256_public,
        sender_rsa_public["n"],
        sender_rsa_public["e"]
    )

    recipient_fingerprint = fingerprint_public_key(
        recipient_id.decode("utf-8"),
        recipient_p256_public,
        recipient_rsa_public["n"],
        recipient_rsa_public["e"]
    )

    ephemeral_private, ephemeral_public = p256_keygen()

    shared_secret = ecdh(
        ephemeral_private,
        recipient_p256_public
    )

    wrapping_key = hkdf(
        shared_secret,
        b"",
        SHARE_INFO,
        32
    )

    nonce = secrets.token_bytes(12)

    aad = make_wrap_aad(
        document_id,
        sender_id,
        recipient_id,
        sender_fingerprint,
        recipient_fingerprint,
        sequence_number,
        timestamp,
        ephemeral_public
    )

    ciphertext, tag = aead_encrypt(
        wrapping_key,
        nonce,
        aad,
        document_key
    )

    wrapped_document_key = nonce + ciphertext + tag

    share = Share(
        document_id,
        sender_id,
        recipient_id,
        sender_fingerprint,
        recipient_fingerprint,
        sequence_number,
        timestamp,
        ephemeral_public,
        wrapped_document_key,
        b""
    )

    share.signature = pss_sign(
        sender_rsa_private,
        share.signed_bytes()
    )

    return share


def verify_share(share, sender_rsa_public):
    return pss_verify(
        sender_rsa_public,
        share.signed_bytes(),
        share.signature
    )


def unwrap_document_key(
    share,
    recipient_p256_private,
    sender_rsa_public
):
    if not verify_share(share, sender_rsa_public):
        raise ValueError("Invalid share signature")

    shared_secret = ecdh(
        recipient_p256_private,
        share.ephemeral_public_key
    )

    wrapping_key = hkdf(
        shared_secret,
        b"",
        SHARE_INFO,
        32
    )

    wrapped = share.wrapped_document_key

    if not isinstance(wrapped, bytes) or len(wrapped) < 28:
        raise ValueError("Invalid wrapped document key")

    nonce = wrapped[:12]
    ciphertext = wrapped[12:-16]
    tag = wrapped[-16:]

    aad = make_wrap_aad(
        share.document_id,
        share.sender_id,
        share.recipient_id,
        share.sender_fingerprint,
        share.recipient_fingerprint,
        share.sequence_number,
        share.timestamp,
        share.ephemeral_public_key
    )

    document_key = aead_decrypt(
        wrapping_key,
        nonce,
        aad,
        ciphertext,
        tag
    )

    if len(document_key) != 32:
        raise ValueError("Invalid document key")

    return document_key


def verify_and_unwrap_share(
    share,
    recipient_p256_private,
    sender_rsa_public,
    freshness_state,
    trusted_keys
):
    sender_id = share.sender_id.decode("utf-8")

    if sender_id not in trusted_keys:
        raise ValueError("Key mismatch")

    if not check_trusted_key(
        trusted_keys,
        sender_id,
        trusted_keys[sender_id]["p256_public_key"],
        sender_rsa_public["n"],
        sender_rsa_public["e"]
    ):
        raise ValueError("Key mismatch")

    trusted_fingerprint = get_fingerprint(
        trusted_keys,
        sender_id
    )

    if share.sender_fingerprint != trusted_fingerprint:
        raise ValueError("Key mismatch")

    if not verify_share(share, sender_rsa_public):
        raise ValueError("Verification failed")

    if not check_freshness(
        freshness_state,
        share.sender_id,
        share.document_id,
        share.sequence_number,
        share.timestamp
    ):
        raise ValueError("Stale object")

    return unwrap_document_key(
        share,
        recipient_p256_private,
        sender_rsa_public
    )