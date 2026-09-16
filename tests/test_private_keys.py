import unittest
from unittest.mock import patch

from crypto.formats import WrappedPrivateKey
from crypto.p256 import p256_keygen
from crypto.rsa_pss import pss_sign, pss_verify, rsa_keygen
from private_keys import (
    BUNDLE_MAX_LEN,
    parse_bundle,
    serialize_bundle,
    unwrap_private_keys,
    wrap_private_keys,
)

USER = "layla"
OTHER_USER = "omar"
WRAP_KEY = bytes(range(32))
OTHER_WRAP_KEY = bytes(range(32, 64))
NONCE = bytes(range(12))


def make_bundle():
    rsa_private, rsa_public = rsa_keygen()
    p256_private, p256_public = p256_keygen()

    return {
        "rsa_private": rsa_private,
        "rsa_public": rsa_public,
        "p256_private": p256_private,
        "p256_public": p256_public,
    }


class TestBundleSerialization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = make_bundle()

    def test_bundle_length_prefixed(self):
        data = serialize_bundle(self.bundle)

        self.assertLessEqual(len(data), BUNDLE_MAX_LEN)
        self.assertEqual(data[0], 2)
        self.assertEqual(data[1], 16)

    def test_bundle_roundtrip(self):
        self.assertEqual(parse_bundle(serialize_bundle(self.bundle)), self.bundle)

    def test_bundle_deterministic(self):
        self.assertEqual(serialize_bundle(self.bundle), serialize_bundle(self.bundle))

    def test_bundle_lengths_within_bound(self):
        other = make_bundle()

        self.assertLessEqual(len(serialize_bundle(other)), BUNDLE_MAX_LEN)

    def test_bundle_rejects_bad_length(self):
        data = serialize_bundle(self.bundle)

        for bad in (b"", data[:-1], data + b"\x00"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    parse_bundle(bad)

    def test_bundle_rejects_wrong_header(self):
        data = bytearray(serialize_bundle(self.bundle))
        data[1] = 4

        with self.assertRaises(ValueError):
            parse_bundle(bytes(data))

    def test_bundle_rejects_inconsistent_rsa(self):
        broken = dict(self.bundle)
        broken["rsa_private"] = dict(self.bundle["rsa_private"])
        broken["rsa_private"]["d"] += 2

        with self.assertRaises(ValueError):
            serialize_bundle(broken)

    def test_bundle_rejects_mismatched_public(self):
        broken = dict(self.bundle)
        broken["rsa_public"] = {"n": self.bundle["rsa_public"]["n"] + 2, "e": 65537}

        with self.assertRaises(ValueError):
            serialize_bundle(broken)

    def test_bundle_rejects_invalid_p256(self):
        for field, value in (
            ("p256_private", bytes(32)),
            ("p256_private", b"\xff" * 32),
            ("p256_private", bytes(31)),
            ("p256_public", b"\x04" + bytes(64)),
            ("p256_public", self.bundle["p256_public"][:64]),
        ):
            broken = dict(self.bundle)
            broken[field] = value

            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    serialize_bundle(broken)

    def test_bundle_rejects_missing_fields(self):
        broken = dict(self.bundle)
        del broken["p256_public"]

        with self.assertRaises(ValueError):
            serialize_bundle(broken)

        broken = dict(self.bundle)
        broken["extra"] = 1

        with self.assertRaises(ValueError):
            serialize_bundle(broken)


class TestWrapping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = make_bundle()
        cls.record = wrap_private_keys(USER, WRAP_KEY, cls.bundle)

    def test_wrap_record_shape(self):
        self.assertEqual(self.record.user_id, b"layla")
        self.assertEqual(len(self.record.nonce), 12)
        self.assertEqual(len(self.record.tag), 16)
        self.assertEqual(len(self.record.ciphertext), len(serialize_bundle(self.bundle)))

    def test_wrap_hides_key_material(self):
        stored = self.record.to_bytes()

        self.assertNotIn(self.bundle["p256_private"], stored)
        self.assertNotIn(WRAP_KEY, stored)

        d_bytes = self.bundle["rsa_private"]["d"].to_bytes(384, "big")
        self.assertNotIn(d_bytes, stored)

    def test_wrap_fresh_nonce(self):
        first = wrap_private_keys(USER, WRAP_KEY, self.bundle)
        second = wrap_private_keys(USER, WRAP_KEY, self.bundle)

        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)

    def test_wrap_fixed_nonce_is_deterministic(self):
        with patch("private_keys.secrets.token_bytes", return_value=NONCE):
            first = wrap_private_keys(USER, WRAP_KEY, self.bundle)
            second = wrap_private_keys(USER, WRAP_KEY, self.bundle)

        self.assertEqual(first.to_bytes(), second.to_bytes())

    def test_wrap_rejects_bad_arguments(self):
        for key in (b"", bytes(31), bytes(33), "x" * 32):
            with self.subTest(wrap_key=len(key)):
                with self.assertRaises(ValueError):
                    wrap_private_keys(USER, key, self.bundle)

        for user_id in ("", b"", None, 5):
            with self.subTest(user_id=user_id):
                with self.assertRaises(ValueError):
                    wrap_private_keys(user_id, WRAP_KEY, self.bundle)


class TestRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = make_bundle()
        cls.record = wrap_private_keys(USER, WRAP_KEY, cls.bundle)
        cls.stored = cls.record.to_bytes()

    def test_recovery_reproduces_keys(self):
        recovered = unwrap_private_keys(USER, WRAP_KEY, self.record)

        self.assertEqual(recovered, self.bundle)
        self.assertEqual(recovered["rsa_private"], self.bundle["rsa_private"])
        self.assertEqual(recovered["p256_private"], self.bundle["p256_private"])

    def test_recovery_from_stored_bytes(self):
        self.assertEqual(
            unwrap_private_keys(USER, WRAP_KEY, self.stored), self.bundle
        )

    def test_recovery_accepts_utf8_user_id(self):
        self.assertEqual(
            unwrap_private_keys(b"layla", WRAP_KEY, self.record), self.bundle
        )

    def test_recovered_key_still_signs(self):
        recovered = unwrap_private_keys(USER, WRAP_KEY, self.record)
        message = b"SecureVault recovery test"

        signature = pss_sign(recovered["rsa_private"], message)

        self.assertTrue(pss_verify(self.bundle["rsa_public"], message, signature))

    def test_recovery_rejects_wrong_wrap_key(self):
        with self.assertRaises(ValueError) as caught:
            unwrap_private_keys(USER, OTHER_WRAP_KEY, self.record)

        self.assertEqual(str(caught.exception), "Verification failed")

    def test_recovery_rejects_altered_nonce(self):
        for index in (0, 5, 11):
            broken = bytearray(self.stored)
            position = broken.index(self.record.nonce)
            broken[position + index] ^= 0x01

            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    unwrap_private_keys(USER, WRAP_KEY, bytes(broken))

    def test_recovery_rejects_altered_ciphertext(self):
        start = self.stored.index(self.record.ciphertext)

        for index in (0, 1, 600, len(self.record.ciphertext) - 1):
            broken = bytearray(self.stored)
            broken[start + index] ^= 0x01

            with self.subTest(index=index):
                with self.assertRaises(ValueError) as caught:
                    unwrap_private_keys(USER, WRAP_KEY, bytes(broken))

                self.assertEqual(str(caught.exception), "Verification failed")

    def test_recovery_rejects_altered_tag(self):
        for index in (0, 8, 15):
            broken = bytearray(self.stored)
            broken[len(broken) - 16 + index] ^= 0x01

            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    unwrap_private_keys(USER, WRAP_KEY, bytes(broken))

    def test_recovery_rejects_truncated_tag(self):
        for bad in (self.stored[:-1], self.stored + b"\x00"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    unwrap_private_keys(USER, WRAP_KEY, bad)

    def test_recovery_rejects_rebound_identity(self):
        # The attacker rewrites the stored identity and keeps the rest.
        rebound = WrappedPrivateKey(
            b"omar", self.record.nonce, self.record.ciphertext, self.record.tag
        )

        with self.assertRaises(ValueError) as caught:
            unwrap_private_keys(OTHER_USER, WRAP_KEY, rebound.to_bytes())

        self.assertEqual(str(caught.exception), "Verification failed")

    def test_recovery_rejects_record_for_another_account(self):
        with self.assertRaises(ValueError) as caught:
            unwrap_private_keys(OTHER_USER, WRAP_KEY, self.record)

        self.assertEqual(str(caught.exception), "Key mismatch")

    def test_recovery_rejects_swapped_record(self):
        other_bundle = make_bundle()
        other_record = wrap_private_keys(OTHER_USER, OTHER_WRAP_KEY, other_bundle)

        with self.assertRaises(ValueError):
            unwrap_private_keys(OTHER_USER, WRAP_KEY, other_record)

    def test_recovery_rejects_wrong_object_type(self):
        broken = bytearray(self.stored)
        broken[1] = 4

        with self.assertRaises(ValueError):
            unwrap_private_keys(USER, WRAP_KEY, bytes(broken))

    def test_recovery_rejects_bad_wrap_key_length(self):
        for key in (b"", bytes(31), bytes(33)):
            with self.subTest(length=len(key)):
                with self.assertRaises(ValueError):
                    unwrap_private_keys(USER, key, self.record)

    def test_recovery_after_rewrap(self):
        # A password change re-wraps the same bundle under a new key.
        rewrapped = wrap_private_keys(USER, OTHER_WRAP_KEY, self.bundle)

        self.assertEqual(
            unwrap_private_keys(USER, OTHER_WRAP_KEY, rewrapped), self.bundle
        )

        with self.assertRaises(ValueError):
            unwrap_private_keys(USER, WRAP_KEY, rewrapped)

class TestAdditionalValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = make_bundle()

    def test_mismatched_p256_pair(self):
        bad = dict(self.bundle)
        _, bad["p256_public"] = p256_keygen()
        with self.assertRaises(ValueError):
            serialize_bundle(bad)

    def test_fields_use_pack_str(self):
        from crypto.formats import unpack_str
        data = serialize_bundle(self.bundle)
        offset = 2
        fields = []
        for _ in range(7):
            field, offset = unpack_str(data, offset)
            fields.append(field)
        self.assertEqual(offset, len(data))
        self.assertEqual(fields[0], self.bundle["p256_private"])
        self.assertEqual(fields[1], self.bundle["p256_public"])
        for name, field in zip(("n", "e", "d", "p", "q"), fields[2:]):
            self.assertEqual(int.from_bytes(field, "big"), self.bundle["rsa_private"][name])
            self.assertNotEqual(field[0], 0)

    def test_oversized_prefix_rejected(self):
        data = serialize_bundle(self.bundle)
        with self.assertRaises(ValueError):
            parse_bundle(data[:2] + b"\xff" * 4 + data[6:])

    def test_no_parse_before_authentication(self):
        record = wrap_private_keys(USER, WRAP_KEY, self.bundle)
        with patch("private_keys.parse_bundle") as parse:
            with self.assertRaises(ValueError):
                unwrap_private_keys(USER, OTHER_WRAP_KEY, record)
            parse.assert_not_called()

    def test_authenticated_bad_bundle_rejected(self):
        from crypto.aead import aead_encrypt
        from private_keys import wrapped_aad
        ciphertext, tag = aead_encrypt(
            WRAP_KEY, NONCE, wrapped_aad(b"layla"), b"invalid bundle")
        record = WrappedPrivateKey(b"layla", NONCE, ciphertext, tag)
        with self.assertRaises(ValueError):
            unwrap_private_keys(USER, WRAP_KEY, record)
