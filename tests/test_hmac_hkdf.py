import hashlib
import hmac as reference_hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def reference_tag(key, data):
    return reference_hmac.new(key, data, hashlib.sha256).digest()


from crypto.hmac_hkdf import (
    compare_tags,
    hmac_sha256,
    hkdf,
    hkdf_expand,
    hkdf_extract,
)

def test_hmac_rfc4231_vectors():
    cases = (
        (
            bytes([0x0B] * 20),
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843",
        ),
        (
            bytes([0xAA] * 20),
            bytes([0xDD] * 50),
            "773ea91e36800e46854db8ebd09181a7"
            "2959098b3ef8c122d9635514ced565fe",
        ),
        (
            bytes(range(1, 26)),
            bytes([0xCD] * 50),
            "82558a389a443c0ea4cc819899f2083a"
            "85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            bytes([0xAA] * 131),
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            bytes([0xAA] * 131),
            b"This is a test using a larger than block-size key and a "
            b"larger than block-size data. The key needs to be hashed "
            b"before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944"
            "bfdc63644f0713938a7f51535c3a35e2",
        ),
    )

    for key, data, expected in cases:
        result = hmac_sha256(key, data)
        assert result.hex() == expected


def test_hmac_empty_inputs():
    assert hmac_sha256(b"", b"") == reference_tag(b"", b"")


def test_hmac_empty_data():
    assert hmac_sha256(b"key", b"") == reference_tag(b"key", b"")


def test_hmac_long_data():
    key = b"SecureVault key"
    data = bytes(range(256)) * 40

    assert hmac_sha256(key, data) == reference_tag(key, data)


def test_hmac_key_lengths():
    data = b"SecureVault test"

    for size in (1, 32, 63, 64, 65, 131, 200):
        key = bytes([size % 256] * size)

        assert hmac_sha256(key, data) == reference_tag(key, data)


def test_compare_tags():
    key = b"SecureVault key"
    data = b"SecureVault test"

    tag = hmac_sha256(key, data)

    assert compare_tags(tag, tag)
    assert not compare_tags(tag, b"wrong")


def test_altered_tag_fails():
    key = b"SecureVault key"
    data = b"SecureVault test"

    tag = hmac_sha256(key, data)

    broken = bytearray(tag)
    broken[0] ^= 1

    assert not compare_tags(tag, bytes(broken))


def test_changed_data_changes_tag():
    key = b"SecureVault key"

    tag1 = hmac_sha256(key, b"hello")
    tag2 = hmac_sha256(key, b"hello!")

    assert not compare_tags(tag1, tag2)


def test_changed_key_changes_tag():
    data = b"SecureVault test"

    tag1 = hmac_sha256(b"key1", data)
    tag2 = hmac_sha256(b"key2", data)

    assert not compare_tags(tag1, tag2)


def test_hkdf_rfc5869_case1():
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))

    prk = hkdf_extract(salt, ikm)

    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )

    result = hkdf(ikm, salt, info, 42)

    assert result.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_rfc5869_case2():
    ikm = bytes(range(0x00, 0x50))
    salt = bytes(range(0x60, 0xB0))
    info = bytes(range(0xB0, 0x100))

    prk = hkdf_extract(salt, ikm)

    assert prk.hex() == (
        "06a6b88c5853361a06104c9ceb35b45c"
        "ef760014904671014a193f40c15fc244"
    )

    result = hkdf(ikm, salt, info, 82)

    assert result.hex() == (
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )


def test_hkdf_rfc5869_case3():
    ikm = bytes([0x0B] * 22)

    prk = hkdf_extract(b"", ikm)

    assert prk.hex() == (
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    )

    result = hkdf(ikm, b"", b"", 42)

    assert result.hex() == (
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_hkdf_empty_salt():
    ikm = b"SecureVault input keying material"

    result1 = hkdf(
        ikm,
        b"",
        b"label",
        32,
    )

    result2 = hkdf(
        ikm,
        None,
        b"label",
        32,
    )

    assert result1 == result2


def test_hkdf_deterministic():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))
    info = b"securevault:v1:auth"

    result1 = hkdf(ikm, salt, info, 32)
    result2 = hkdf(ikm, salt, info, 32)

    assert result1 == result2


def test_hkdf_different_info():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))

    auth = hkdf(
        ikm,
        salt,
        b"securevault:v1:auth",
        32,
    )

    wrap = hkdf(
        ikm,
        salt,
        b"securevault:v1:wrap",
        32,
    )

    assert auth != wrap


def test_hkdf_different_salt():
    ikm = b"SecureVault input keying material"

    result1 = hkdf(
        ikm,
        bytes(range(16)),
        b"securevault:v1:auth",
        32,
    )

    result2 = hkdf(
        ikm,
        bytes(range(16, 32)),
        b"securevault:v1:auth",
        32,
    )

    assert result1 != result2


def test_hkdf_prefix():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))
    info = b"securevault:v1:auth"

    short_result = hkdf(
        ikm,
        salt,
        info,
        40,
    )

    long_result = hkdf(
        ikm,
        salt,
        info,
        120,
    )

    assert short_result == long_result[:40]


def test_hkdf_expand_matches_hkdf():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))
    info = b"securevault:v1:auth"

    prk = hkdf_extract(salt, ikm)

    result1 = hkdf_expand(prk, info, 64)
    result2 = hkdf(ikm, salt, info, 64)

    assert result1 == result2


def test_hkdf_length():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))

    for length in (1, 16, 32, 33, 64, 100, 255):
        result = hkdf(
            ikm,
            salt,
            b"info",
            length,
        )

        assert len(result) == length


def test_hkdf_invalid_length():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))

    for length in (-1, 8161, 10000, 1.5, None, True):
        try:
            hkdf(
                ikm,
                salt,
                b"info",
                length,
            )
            assert False
        except ValueError:
            pass


def test_hkdf_maximum_length():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))

    result = hkdf(
        ikm,
        salt,
        b"info",
        8160,
    )

    assert len(result) == 8160
    
def test_hkdf_reference_library():
    ikm = b"SecureVault input keying material"
    salt = bytes(range(16))
    info = b"securevault:test"

    for length in (1, 16, 32, 33, 64, 100, 255):
        expected = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(ikm)

        assert hkdf(ikm, salt, info, length) == expected
        
def test_hkdf_expand_rejects_short_prk():
    for size in (0, 1, 16, 31):
        try:
            hkdf_expand(b"\x01" * size, b"info", 32)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"hkdf_expand accepted a {size}-byte PRK"
            )