import pytest

from accounts import public_key_fingerprint
from crypto.formats import PublicKey
from crypto.p256 import p256_keygen
from crypto.rsa_pss import i2osp, rsa_keygen
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


def make_rsa_key():
    rsa_private, rsa_public = rsa_keygen()

    return rsa_public["n"], rsa_public["e"]


def make_identity(user_id):
    p256_private, p256_public = p256_keygen()
    rsa_public_key, rsa_public_exponent = make_rsa_key()

    record = PublicKey(
        user_id.encode("utf-8"),
        p256_public,
        i2osp(rsa_public_key, 384),
        i2osp(rsa_public_exponent, 3)
    )

    return {
        "user_id": user_id,
        "p256_public": p256_public,
        "rsa_public_key": rsa_public_key,
        "rsa_public_exponent": rsa_public_exponent,
        "record": record
    }


def test_fingerprint_length():
    identity = make_identity("yaqeen")

    fingerprint = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert len(fingerprint) == 32


def test_fingerprint_hex_length():
    identity = make_identity("yaqeen")

    fingerprint = fingerprint_hex(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert len(fingerprint) == 64
    assert isinstance(fingerprint, str)


def test_same_key_same_fingerprint():
    identity = make_identity("yaqeen")

    fingerprint1 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    fingerprint2 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert fingerprint1 == fingerprint2


def test_different_user_changes_fingerprint():
    identity = make_identity("yaqeen")

    fingerprint1 = fingerprint_public_key(
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    fingerprint2 = fingerprint_public_key(
        "other",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert fingerprint1 != fingerprint2


def test_different_p256_key_changes_fingerprint():
    identity1 = make_identity("yaqeen")
    identity2 = make_identity("yaqeen")

    fingerprint1 = fingerprint_public_key(
        identity1["user_id"],
        identity1["p256_public"],
        identity1["rsa_public_key"],
        identity1["rsa_public_exponent"]
    )

    fingerprint2 = fingerprint_public_key(
        identity2["user_id"],
        identity2["p256_public"],
        identity1["rsa_public_key"],
        identity1["rsa_public_exponent"]
    )

    assert fingerprint1 != fingerprint2


def test_different_rsa_key_changes_fingerprint():
    identity = make_identity("yaqeen")

    fingerprint1 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    fingerprint2 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"] + 1,
        identity["rsa_public_exponent"]
    )

    assert fingerprint1 != fingerprint2


def test_different_rsa_exponent_changes_fingerprint():
    identity = make_identity("yaqeen")

    fingerprint1 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    fingerprint2 = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        3
    )

    assert fingerprint1 != fingerprint2


def test_fingerprint_matches_accounts():
    identity = make_identity("yaqeen")

    trust_fingerprint = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    account_fingerprint = public_key_fingerprint(
        identity["record"]
    )

    assert trust_fingerprint == account_fingerprint


def test_fingerprint_matches_serialized_public_key():
    identity = make_identity("yaqeen")

    serialized = identity["record"].to_bytes()

    account_fingerprint = public_key_fingerprint(serialized)

    trust_fingerprint = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert account_fingerprint == trust_fingerprint


def test_first_key_is_trusted():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    result = trust_first_key(
        trusted_keys,
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert result is True
    assert "yaqeen" in trusted_keys


def test_first_key_stores_correct_information():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    stored = trusted_keys["yaqeen"]

    assert stored["p256_public_key"] == identity["p256_public"]
    assert stored["rsa_public_key"] == identity["rsa_public_key"]
    assert stored["rsa_public_exponent"] == identity["rsa_public_exponent"]

    expected = fingerprint_public_key(
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert stored["fingerprint"] == expected
    assert stored["verified"] is False


def test_first_key_is_not_verified():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert is_key_verified(trusted_keys, "yaqeen") is False


def test_same_key_is_trusted():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = check_trusted_key(
        trusted_keys,
        identity["user_id"],
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert result is True


def test_changed_user_id_is_rejected():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = check_trusted_key(
        trusted_keys,
        "other",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert result is False


def test_changed_p256_key_is_rejected():
    identity1 = make_identity("yaqeen")
    identity2 = make_identity("yaqeen")

    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity1["p256_public"],
        identity1["rsa_public_key"],
        identity1["rsa_public_exponent"]
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        identity2["p256_public"],
        identity1["rsa_public_key"],
        identity1["rsa_public_exponent"]
    )

    assert result is False


def test_changed_rsa_key_is_rejected():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"] + 1,
        identity["rsa_public_exponent"]
    )

    assert result is False


def test_changed_rsa_exponent_is_rejected():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        3
    )

    assert result is False


def test_unknown_user_is_not_trusted():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    result = check_trusted_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert result is False


def test_second_first_contact_is_rejected():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    first_result = trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    second_result = trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert first_result is True
    assert second_result is False


def test_mark_key_verified():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = mark_key_verified(trusted_keys, "yaqeen")

    assert result is True
    assert is_key_verified(trusted_keys, "yaqeen") is True


def test_mark_unknown_key_verified_fails():
    trusted_keys = {}

    result = mark_key_verified(
        trusted_keys,
        "yaqeen"
    )

    assert result is False


def test_get_fingerprint():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    fingerprint = get_fingerprint(
        trusted_keys,
        "yaqeen"
    )

    expected = fingerprint_public_key(
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    assert fingerprint == expected


def test_get_unknown_fingerprint_returns_none():
    trusted_keys = {}

    assert get_fingerprint(
        trusted_keys,
        "yaqeen"
    ) is None


def test_remove_trusted_key():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    result = remove_trusted_key(
        trusted_keys,
        "yaqeen"
    )

    assert result is True
    assert "yaqeen" not in trusted_keys


def test_remove_unknown_key_fails():
    trusted_keys = {}

    result = remove_trusted_key(
        trusted_keys,
        "yaqeen"
    )

    assert result is False


def test_removed_key_is_not_trusted():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    remove_trusted_key(
        trusted_keys,
        "yaqeen"
    )

    assert is_key_verified(
        trusted_keys,
        "yaqeen"
    ) is False

    assert get_fingerprint(
        trusted_keys,
        "yaqeen"
    ) is None


def test_removed_key_cannot_be_checked():
    identity = make_identity("yaqeen")
    trusted_keys = {}

    trust_first_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    )

    remove_trusted_key(
        trusted_keys,
        "yaqeen"
    )

    assert check_trusted_key(
        trusted_keys,
        "yaqeen",
        identity["p256_public"],
        identity["rsa_public_key"],
        identity["rsa_public_exponent"]
    ) is False


def test_two_users_can_be_trusted():
    yaqeen = make_identity("yaqeen")
    aseel = make_identity("aseel")

    trusted_keys = {}

    result1 = trust_first_key(
        trusted_keys,
        yaqeen["user_id"],
        yaqeen["p256_public"],
        yaqeen["rsa_public_key"],
        yaqeen["rsa_public_exponent"]
    )

    result2 = trust_first_key(
        trusted_keys,
        aseel["user_id"],
        aseel["p256_public"],
        aseel["rsa_public_key"],
        aseel["rsa_public_exponent"]
    )

    assert result1 is True
    assert result2 is True

    assert "yaqeen" in trusted_keys
    assert "aseel" in trusted_keys

    assert check_trusted_key(
        trusted_keys,
        yaqeen["user_id"],
        yaqeen["p256_public"],
        yaqeen["rsa_public_key"],
        yaqeen["rsa_public_exponent"]
    ) is True

    assert check_trusted_key(
        trusted_keys,
        aseel["user_id"],
        aseel["p256_public"],
        aseel["rsa_public_key"],
        aseel["rsa_public_exponent"]
    ) is True


def test_invalid_user_id_type():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            123,
            identity["p256_public"],
            identity["rsa_public_key"],
            identity["rsa_public_exponent"]
        )


def test_invalid_p256_type():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            "yaqeen",
            "not bytes",
            identity["rsa_public_key"],
            identity["rsa_public_exponent"]
        )


def test_invalid_p256_length():
    identity = make_identity("yaqeen")

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            b"",
            identity["rsa_public_key"],
            identity["rsa_public_exponent"]
        )


def test_invalid_p256_point():
    identity = make_identity("yaqeen")

    invalid_key = b"\x04" + b"\x00" * 64

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            invalid_key,
            identity["rsa_public_key"],
            identity["rsa_public_exponent"]
        )


def test_invalid_rsa_key_type():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            "not integer",
            identity["rsa_public_exponent"]
        )


def test_boolean_rsa_key_is_rejected():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            True,
            identity["rsa_public_exponent"]
        )


def test_negative_rsa_key_is_rejected():
    identity = make_identity("yaqeen")

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            -1,
            identity["rsa_public_exponent"]
        )


def test_rsa_key_too_large_is_rejected():
    identity = make_identity("yaqeen")

    too_large = 1 << 3072

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            too_large,
            identity["rsa_public_exponent"]
        )


def test_invalid_rsa_exponent_type():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            identity["rsa_public_key"],
            "65537"
        )


def test_boolean_rsa_exponent_is_rejected():
    identity = make_identity("yaqeen")

    with pytest.raises(TypeError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            identity["rsa_public_key"],
            True
        )


def test_non_positive_rsa_exponent_is_rejected():
    identity = make_identity("yaqeen")

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            identity["rsa_public_key"],
            0
        )


def test_rsa_exponent_too_large_is_rejected():
    identity = make_identity("yaqeen")

    too_large = 1 << 24

    with pytest.raises(ValueError):
        fingerprint_public_key(
            "yaqeen",
            identity["p256_public"],
            identity["rsa_public_key"],
            too_large
        )