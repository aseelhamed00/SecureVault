from trust import (
    fingerprint_public_key,
    fingerprint_hex,
    trust_first_key,
    check_trusted_key,
    is_key_verified,
    mark_key_verified,
    get_fingerprint,
    remove_trusted_key
)

from crypto.p256 import p256_keygen


def make_rsa_key():
    rsa_public_key = (1 << 3071) + 12345
    rsa_public_exponent = 65537
    return rsa_public_key, rsa_public_exponent


def test_fingerprint_length():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert len(fingerprint) == 32


def test_same_key_same_fingerprint():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    fingerprint2 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert fingerprint1 == fingerprint2


def test_fingerprint_hex_length():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint = fingerprint_hex(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert len(fingerprint) == 64


def test_different_user_changes_fingerprint():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    fingerprint2 = fingerprint_public_key(
        "other",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert fingerprint1 != fingerprint2


def test_different_p256_key_changes_fingerprint():
    private_key1, p256_public_key1 = p256_keygen()
    private_key2, p256_public_key2 = p256_keygen()

    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        p256_public_key1,
        rsa_public_key,
        rsa_public_exponent
    )

    fingerprint2 = fingerprint_public_key(
        "yaqeen",
        p256_public_key2,
        rsa_public_key,
        rsa_public_exponent
    )

    assert fingerprint1 != fingerprint2


def test_different_rsa_key_changes_fingerprint():
    private_key, p256_public_key = p256_keygen()

    rsa_public_key1, rsa_public_exponent = make_rsa_key()
    rsa_public_key2 = rsa_public_key1 + 1

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key1,
        rsa_public_exponent
    )

    fingerprint2 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key2,
        rsa_public_exponent
    )

    assert fingerprint1 != fingerprint2


def test_different_rsa_exponent_changes_fingerprint():
    private_key, p256_public_key = p256_keygen()

    rsa_public_key, rsa_public_exponent = make_rsa_key()

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    fingerprint2 = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        3
    )

    assert fingerprint1 != fingerprint2


def test_first_key_is_trusted():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    result = trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert result is True
    assert "yaqeen" in trusted_keys


def test_first_key_is_not_verified():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert is_key_verified(trusted_keys, "yaqeen") is False


def test_same_key_is_trusted():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert result is True


def test_changed_p256_key_is_rejected():
    private_key1, p256_public_key1 = p256_keygen()
    private_key2, p256_public_key2 = p256_keygen()

    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key1,
        rsa_public_key,
        rsa_public_exponent
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        p256_public_key2,
        rsa_public_key,
        rsa_public_exponent
    )

    assert result is False


def test_changed_rsa_key_is_rejected():
    private_key, p256_public_key = p256_keygen()

    rsa_public_key1, rsa_public_exponent = make_rsa_key()
    rsa_public_key2 = rsa_public_key1 + 1

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key1,
        rsa_public_exponent
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key2,
        rsa_public_exponent
    )

    assert result is False


def test_unknown_user_is_not_trusted():
    trusted_keys = {}

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        b"",
        1,
        65537
    )

    assert result is False


def test_second_first_contact_is_rejected():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    first_result = trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    second_result = trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert first_result is True
    assert second_result is False


def test_mark_key_verified():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    result = mark_key_verified(trusted_keys, "yaqeen")

    assert result is True
    assert is_key_verified(trusted_keys, "yaqeen") is True


def test_mark_unknown_key_verified_fails():
    trusted_keys = {}

    result = mark_key_verified(trusted_keys, "yaqeen")

    assert result is False


def test_get_fingerprint():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    fingerprint = get_fingerprint(trusted_keys, "yaqeen")

    expected = fingerprint_public_key(
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    assert fingerprint == expected


def test_remove_trusted_key():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    result = remove_trusted_key(trusted_keys, "yaqeen")

    assert result is True
    assert "yaqeen" not in trusted_keys


def test_removed_key_is_not_trusted():
    private_key, p256_public_key = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        p256_public_key,
        rsa_public_key,
        rsa_public_exponent
    )

    remove_trusted_key(trusted_keys, "yaqeen")

    assert is_key_verified(trusted_keys, "yaqeen") is False
    assert get_fingerprint(trusted_keys, "yaqeen") is None
    
def test_two_users_can_be_trusted():
    yaqeen_private, yaqeen_p256 = p256_keygen()
    aseel_private, aseel_p256 = p256_keygen()

    yaqeen_rsa, yaqeen_exponent = make_rsa_key()
    aseel_rsa, aseel_exponent = make_rsa_key()

    trusted_keys = {}

    result1 = trust_first_key(
        trusted_keys,
        "yaqeen",
        yaqeen_p256,
        yaqeen_rsa,
        yaqeen_exponent
    )

    result2 = trust_first_key(
        trusted_keys,
        "aseel",
        aseel_p256,
        aseel_rsa,
        aseel_exponent
    )

    assert result1 is True
    assert result2 is True

    assert "yaqeen" in trusted_keys
    assert "aseel" in trusted_keys

    assert check_trusted_key(
        trusted_keys,
        "yaqeen",
        yaqeen_p256,
        yaqeen_rsa,
        yaqeen_exponent
    ) is True

    assert check_trusted_key(
        trusted_keys,
        "aseel",
        aseel_p256,
        aseel_rsa,
        aseel_exponent
    ) is True