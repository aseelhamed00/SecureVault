import pytest

from crypto.p256 import (
    P,
    N,
    G,
    point_is_on_curve,
    point_add,
    scalar_mult,
    p256_keygen,
    p256_validate_public,
    ecdh
)


def test_generator_is_on_curve():
    assert point_is_on_curve(G) is True


def test_point_at_infinity_is_valid():
    assert point_is_on_curve(None) is True


def test_scalar_zero_returns_infinity():
    result = scalar_mult(0, G)

    assert result is None


def test_scalar_one_returns_generator():
    result = scalar_mult(1, G)

    assert result == G


def test_point_add_infinity():
    assert point_add(None, G) == G
    assert point_add(G, None) == G


def test_generator_plus_negative_generator():
    x, y = G

    negative_g = (x, (-y) % P)

    result = point_add(G, negative_g)

    assert result is None


def test_double_generator():
    result = point_add(G, G)

    assert result is not None
    assert point_is_on_curve(result) is True


def test_scalar_multiplication_result_is_on_curve():
    result = scalar_mult(12345, G)

    assert result is not None
    assert point_is_on_curve(result) is True


def test_n_times_generator_is_infinity():
    result = scalar_mult(N, G)

    assert result is None


def test_keygen_returns_key_pair():
    private_key, public_key = p256_keygen()

    assert private_key is not None
    assert public_key is not None


def test_private_key_length():
    private_key, public_key = p256_keygen()

    assert len(private_key) == 32


def test_public_key_length():
    private_key, public_key = p256_keygen()

    assert len(public_key) == 65


def test_public_key_prefix():
    private_key, public_key = p256_keygen()

    assert public_key[0] == 0x04


def test_generated_public_key_is_valid():
    private_key, public_key = p256_keygen()

    assert p256_validate_public(public_key) is True


def test_invalid_public_key_length():
    invalid_key = bytes(64)

    assert p256_validate_public(invalid_key) is False


def test_invalid_public_key_prefix():
    private_key, public_key = p256_keygen()

    invalid_key = bytes([0x05]) + public_key[1:]

    assert p256_validate_public(invalid_key) is False


def test_invalid_public_key_not_on_curve():
    invalid_key = (
        b"\x04"
        + (1).to_bytes(32, "big")
        + (1).to_bytes(32, "big")
    )

    assert p256_validate_public(invalid_key) is False


def test_ecdh_shared_secret_matches():
    alice_private, alice_public = p256_keygen()
    bob_private, bob_public = p256_keygen()

    alice_secret = ecdh(
        alice_private,
        bob_public
    )

    bob_secret = ecdh(
        bob_private,
        alice_public
    )

    assert alice_secret == bob_secret


def test_ecdh_secret_length():
    alice_private, alice_public = p256_keygen()
    bob_private, bob_public = p256_keygen()

    secret = ecdh(
        alice_private,
        bob_public
    )

    assert len(secret) == 32


def test_different_private_keys_produce_different_public_keys():
    private_1, public_1 = p256_keygen()
    private_2, public_2 = p256_keygen()

    assert private_1 != private_2
    assert public_1 != public_2


def test_different_ecdh_pairs_produce_different_secrets():
    alice_private, alice_public = p256_keygen()
    bob_private, bob_public = p256_keygen()

    charlie_private, charlie_public = p256_keygen()

    alice_secret = ecdh(
        alice_private,
        bob_public
    )

    charlie_secret = ecdh(
        charlie_private,
        bob_public
    )

    assert alice_secret != charlie_secret


def test_invalid_private_key_length():
    _, public_key = p256_keygen()

    with pytest.raises(ValueError):
        ecdh(bytes(31), public_key)


def test_zero_private_key_is_rejected():
    _, public_key = p256_keygen()

    with pytest.raises(ValueError):
        ecdh(bytes(32), public_key)


def test_private_key_equal_n_is_rejected():
    _, public_key = p256_keygen()

    private_key = N.to_bytes(32, "big")

    with pytest.raises(ValueError):
        ecdh(private_key, public_key)


def test_invalid_public_key_is_rejected_by_ecdh():
    private_key, _ = p256_keygen()

    invalid_public_key = bytes(65)

    with pytest.raises(ValueError):
        ecdh(private_key, invalid_public_key)

def test_modified_public_key_is_rejected():
    private_key, public_key = p256_keygen()

    bad_key = bytearray(public_key)

    # Change one bit in X
    bad_key[10] ^= 1

    bad_key = bytes(bad_key)

    assert p256_validate_public(bad_key) is False