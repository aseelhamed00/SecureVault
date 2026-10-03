import secrets

from crypto.rsa_pss import rsa_keygen
from crypto.p256 import p256_keygen
from crypto.aead import (
    aead_encrypt,
    aead_decrypt
)

from sharing import (
    create_share,
    verify_share,
    unwrap_document_key,
    verify_and_unwrap_share
)


def test_create_and_unwrap_share():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_p256_private, sender_p256_public = p256_keygen()
    recipient_p256_private, recipient_p256_public = p256_keygen()

    document_id = b"1234567890abcdef"
    sender_id = b"alice"
    recipient_id = b"bob"

    document_key = b"A" * 32

    share = create_share(
        document_id,
        sender_id,
        recipient_id,
        document_key,
        sender_p256_public,
        recipient_p256_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    assert verify_share(
        share,
        sender_rsa_public
    )

    result = unwrap_document_key(
        share,
        recipient_p256_private,
        sender_rsa_public
    )

    assert result == document_key


def test_tampered_sequence_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"B" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    share.sequence_number = 2

    assert verify_share(
        share,
        sender_rsa_public
    ) is False


def test_tampered_wrapped_key_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"C" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    wrapped = bytearray(share.wrapped_document_key)
    wrapped[20] ^= 1
    share.wrapped_document_key = bytes(wrapped)

    assert verify_share(
        share,
        sender_rsa_public
    ) is False


def test_wrong_recipient_cannot_unwrap():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()
    wrong_private, wrong_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"D" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    try:
        unwrap_document_key(
            share,
            wrong_private,
            sender_rsa_public
        )
        assert False
    except ValueError:
        pass


def test_share_serialization():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"E" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        5,
        2000
    )

    data = share.to_bytes()
    restored = type(share).from_bytes(data)

    assert restored.document_id == share.document_id
    assert restored.sender_id == share.sender_id
    assert restored.recipient_id == share.recipient_id
    assert restored.sender_fingerprint == share.sender_fingerprint
    assert restored.recipient_fingerprint == share.recipient_fingerprint
    assert restored.sequence_number == share.sequence_number
    assert restored.timestamp == share.timestamp
    assert restored.ephemeral_public_key == share.ephemeral_public_key
    assert restored.wrapped_document_key == share.wrapped_document_key
    assert restored.signature == share.signature

    assert verify_share(
        restored,
        sender_rsa_public
    )


def test_aead_tag_tampering():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    plaintext = b"secret document key"
    aad = b"securevault test"

    ciphertext, tag = aead_encrypt(
        key,
        nonce,
        aad,
        plaintext
    )

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 1
    bad_tag = bytes(bad_tag)

    try:
        aead_decrypt(
            key,
            nonce,
            aad,
            ciphertext,
            bad_tag
        )
        assert False
    except ValueError:
        pass


def test_tampered_metadata_cannot_unwrap():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"F" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    share.timestamp = 2000

    try:
        unwrap_document_key(
            share,
            recipient_private,
            sender_rsa_public
        )
        assert False
    except ValueError:
        pass


def test_broken_share_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"G" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    broken_signature = bytearray(share.signature)
    broken_signature[0] ^= 1
    share.signature = bytes(broken_signature)

    assert verify_share(
        share,
        sender_rsa_public
    ) is False

    try:
        unwrap_document_key(
            share,
            recipient_private,
            sender_rsa_public
        )
        assert False
    except ValueError:
        pass


def test_replayed_share_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"H" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    freshness_state = {}

    trusted_keys = {}

    trusted_keys["alice"] = {
        "p256_public_key": sender_public,
        "rsa_public_key": sender_rsa_public["n"],
        "rsa_public_exponent": sender_rsa_public["e"],
        "fingerprint": share.sender_fingerprint,
        "verified": False
    }

    result = verify_and_unwrap_share(
        share,
        recipient_private,
        sender_rsa_public,
        freshness_state,
        trusted_keys
    )

    assert result == document_key

    try:
        verify_and_unwrap_share(
            share,
            recipient_private,
            sender_rsa_public,
            freshness_state,
            trusted_keys
        )
        assert False
    except ValueError:
        pass


def test_untrusted_sender_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"I" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    freshness_state = {}
    trusted_keys = {}

    try:
        verify_and_unwrap_share(
            share,
            recipient_private,
            sender_rsa_public,
            freshness_state,
            trusted_keys
        )
        assert False
    except ValueError:
        pass


def test_changed_sender_key_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"J" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    freshness_state = {}

    trusted_keys = {}

    trusted_keys["alice"] = {
        "p256_public_key": sender_public,
        "rsa_public_key": sender_rsa_public["n"],
        "rsa_public_exponent": sender_rsa_public["e"],
        "fingerprint": share.sender_fingerprint,
        "verified": False
    }

    changed_rsa_private, changed_rsa_public = rsa_keygen()

    try:
        verify_and_unwrap_share(
            share,
            recipient_private,
            changed_rsa_public,
            freshness_state,
            trusted_keys
        )
        assert False
    except ValueError:
        pass


def test_changed_sender_fingerprint_is_rejected():
    sender_rsa_private, sender_rsa_public = rsa_keygen()
    recipient_rsa_private, recipient_rsa_public = rsa_keygen()

    sender_private, sender_public = p256_keygen()
    recipient_private, recipient_public = p256_keygen()

    document_id = b"1234567890abcdef"
    document_key = b"K" * 32

    share = create_share(
        document_id,
        b"alice",
        b"bob",
        document_key,
        sender_public,
        recipient_public,
        sender_rsa_private,
        sender_rsa_public,
        recipient_rsa_public,
        1,
        1000
    )

    freshness_state = {}

    trusted_keys = {}

    trusted_keys["alice"] = {
        "p256_public_key": sender_public,
        "rsa_public_key": sender_rsa_public["n"],
        "rsa_public_exponent": sender_rsa_public["e"],
        "fingerprint": share.sender_fingerprint,
        "verified": False
    }

    changed = bytearray(share.sender_fingerprint)
    changed[0] ^= 1
    share.sender_fingerprint = bytes(changed)

    try:
        verify_and_unwrap_share(
            share,
            recipient_private,
            sender_rsa_public,
            freshness_state,
            trusted_keys
        )
        assert False
    except ValueError:
        pass