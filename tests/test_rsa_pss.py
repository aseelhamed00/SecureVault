import hashlib
import math
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from crypto.rsa_pss import (
    generate_prime,
    is_probable_prime,
    mgf1,
    pss_decode,
    pss_encode,
    pss_sign,
    pss_verify,
    rsa_keygen,
)


def reference_key(key):
    return rsa.RSAPrivateNumbers(
        p=key["p"],
        q=key["q"],
        d=key["d"],
        dmp1=key["d"] % (key["p"] - 1),
        dmq1=key["d"] % (key["q"] - 1),
        iqmp=pow(key["q"], -1, key["p"]),
        public_numbers=rsa.RSAPublicNumbers(key["e"], key["n"]),
    ).private_key()


def reference_mgf1(seed, length):
    out = b""
    counter = 0

    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1

    return out[:length]


def pss_scheme(salt_length=32):
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=salt_length,
    )


class TestKeygenHelpers(unittest.TestCase):
    def test_keygen_primality(self):
        for n in (2, 3, 5, 17, 97, 65537):
            with self.subTest(n=n):
                self.assertTrue(is_probable_prime(n))

        for n in (
            -1, 0, 1, 4, 9, 15, 25, 49,
            341, 561, 1105, 1729, 1763,
        ):
            with self.subTest(n=n):
                self.assertFalse(is_probable_prime(n))

    def test_keygen_invalid_parameters(self):
        for rounds in (0, -1):
            with self.assertRaises(ValueError):
                is_probable_prime(97, rounds)

        with self.assertRaises(ValueError):
            generate_prime(2)

        with self.assertRaises(ValueError):
            generate_prime(32, 4)

    def test_keygen_small_prime(self):
        p = generate_prime(16)

        self.assertEqual(p.bit_length(), 16)
        self.assertEqual(p % 2, 1)
        self.assertEqual(math.gcd(65537, p - 1), 1)

        self.assertTrue(
            all(
                p % divisor
                for divisor in range(2, math.isqrt(p) + 1)
            )
        )


class TestKeygenRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = [rsa_keygen(), rsa_keygen()]

    def test_keygen_structure(self):
        for private, public in self.pairs:
            p = private["p"]
            q = private["q"]

            self.assertNotEqual(p, q)
            self.assertEqual(p.bit_length(), 1536)
            self.assertEqual(q.bit_length(), 1536)

            self.assertEqual(public["n"], p * q)
            self.assertEqual(public["n"].bit_length(), 3072)
            self.assertEqual(public["e"], 65537)

            self.assertEqual(private["n"], public["n"])
            self.assertEqual(private["e"], public["e"])

            order = math.lcm(p - 1, q - 1)

            self.assertEqual(math.gcd(public["e"], order), 1)
            self.assertEqual(
                (private["d"] * public["e"]) % order,
                1,
            )

    def test_keygen_independent_pairs(self):
        n1 = self.pairs[0][1]["n"]
        n2 = self.pairs[1][1]["n"]

        self.assertNotEqual(n1, n2)
        self.assertEqual(math.gcd(n1, n2), 1)

    def test_keygen_reference(self):
        for private, public in self.pairs:
            key = reference_key(private)
            self.assertEqual(key.key_size, 3072)

            scheme = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            )

            message = b"RSA key generation test"

            signature = key.sign(
                message,
                scheme,
                hashes.SHA256(),
            )

            self.assertEqual(len(signature), 384)

            key.public_key().verify(
                signature,
                message,
                scheme,
                hashes.SHA256(),
            )

    def test_keygen_corrupted_key(self):
        bad = dict(self.pairs[0][0])
        bad["d"] += 2

        with self.assertRaises(ValueError):
            reference_key(bad)


class TestMGF1(unittest.TestCase):
    def test_mgf1_vectors(self):
        cases = (
            (b"foo", 5, "3bdaba83cf"),
            (
                b"bar",
                50,
                "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10"
                "dc724b155f9f6069f289d61daca0cb814502ef04eae1",
            ),
        )

        for seed, length, expected in cases:
            with self.subTest(seed=seed):
                self.assertEqual(mgf1(seed, length).hex(), expected)

    def test_mgf1_lengths(self):
        for seed in (b"", b"seed", b"SecureVault test", bytes(range(32))):
            for length in (0, 1, 31, 32, 33, 64, 65, 351):
                with self.subTest(seed=seed, length=length):
                    out = mgf1(seed, length)

                    self.assertEqual(len(out), length)
                    self.assertEqual(out, reference_mgf1(seed, length))

    def test_mgf1_prefix_property(self):
        seed = b"SecureVault test"

        self.assertEqual(mgf1(seed, 100), mgf1(seed, 200)[:100])
        self.assertNotEqual(mgf1(seed, 32), mgf1(seed + b"!", 32))

    def test_mgf1_invalid_length(self):
        for length in (-1, 1.5, None):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    mgf1(b"seed", length)


class TestPSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.public = rsa_keygen()
        cls.reference = reference_key(cls.private)
        cls.other_private, cls.other_public = rsa_keygen()

    def messages(self):
        return (b"", b"SecureVault test", b"\x00" * 64, bytes(range(256)) * 8)

    def test_pss_sign_and_verify(self):
        for message in self.messages():
            with self.subTest(message=message[:16]):
                signature = pss_sign(self.private, message)

                self.assertEqual(len(signature), 384)
                self.assertTrue(pss_verify(self.public, message, signature))

    def test_pss_fresh_salt(self):
        message = b"SecureVault test"
        first = pss_sign(self.private, message)
        second = pss_sign(self.private, message)

        self.assertNotEqual(first, second)
        self.assertTrue(pss_verify(self.public, message, first))
        self.assertTrue(pss_verify(self.public, message, second))

    def test_pss_verified_by_reference(self):
        for message in self.messages():
            with self.subTest(message=message[:16]):
                signature = pss_sign(self.private, message)

                self.reference.public_key().verify(
                    signature,
                    message,
                    pss_scheme(),
                    hashes.SHA256(),
                )

    def test_pss_verifies_reference_signatures(self):
        for message in self.messages():
            with self.subTest(message=message[:16]):
                signature = self.reference.sign(
                    message,
                    pss_scheme(),
                    hashes.SHA256(),
                )

                self.assertTrue(pss_verify(self.public, message, signature))

    def test_pss_deterministic_against_reference(self):
        message = b"SecureVault test"

        em = pss_encode(
            message,
            self.public["n"].bit_length() - 1,
            salt=b"",
        )
        mine = pow(
            int.from_bytes(em, "big"),
            self.private["d"],
            self.public["n"],
        ).to_bytes(384, "big")
        theirs = self.reference.sign(
            message,
            pss_scheme(0),
            hashes.SHA256(),
        )

        self.assertEqual(mine, theirs)

    def test_pss_encode_fixed_salt(self):
        message = b"SecureVault test"
        salt = bytes(range(32))

        first = pss_encode(message, 3071, salt)
        second = pss_encode(message, 3071, salt)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 384)
        self.assertEqual(first[-1], 0xBC)
        self.assertEqual(first[0] & 0x80, 0)

    def test_pss_wrong_message(self):
        signature = pss_sign(self.private, b"SecureVault test")

        self.assertFalse(
            pss_verify(self.public, b"SecureVault Test", signature)
        )
        self.assertFalse(pss_verify(self.public, b"", signature))

    def test_pss_wrong_key(self):
        message = b"SecureVault test"
        signature = pss_sign(self.private, message)
        other_signature = pss_sign(self.other_private, message)

        self.assertFalse(pss_verify(self.other_public, message, signature))
        self.assertFalse(pss_verify(self.public, message, other_signature))

    def test_pss_altered_signature(self):
        message = b"SecureVault test"
        signature = pss_sign(self.private, message)

        for index in (0, 1, 200, 351, 382, 383):
            with self.subTest(index=index):
                broken = bytearray(signature)
                broken[index] ^= 0x01

                self.assertFalse(
                    pss_verify(self.public, message, bytes(broken))
                )

    def test_pss_wrong_length_signature(self):
        message = b"SecureVault test"
        signature = pss_sign(self.private, message)

        for bad in (b"", signature[:-1], signature + b"\x00", b"\x00" * 384):
            with self.subTest(length=len(bad)):
                self.assertFalse(pss_verify(self.public, message, bad))

    def test_pss_signature_out_of_range(self):
        message = b"SecureVault test"
        n = self.public["n"]

        for value in (n, n + 1, (1 << 3072) - 1):
            with self.subTest(value=value % 1000):
                signature = value.to_bytes(384, "big")

                self.assertGreaterEqual(int.from_bytes(signature, "big"), n)
                self.assertFalse(pss_verify(self.public, message, signature))

    def test_pss_malformed_encodings(self):
        message = b"SecureVault test"
        salt = bytes(range(32))
        em = bytearray(pss_encode(message, 3071, salt))

        broken = [
            ("trailer", 383, 0x01),
            ("top bit", 0, 0x80),
            ("padding", 5, 0x01),
            ("separator", 351 - 33, 0x02),
            ("hash", 360, 0x01),
        ]

        for name, index, mask in broken:
            with self.subTest(case=name):
                bad = bytearray(em)
                bad[index] ^= mask

                self.assertFalse(
                    pss_decode(message, bytes(bad), 3071),
                    msg=name,
                )

                forged = int.from_bytes(bytes(bad), "big")

                if forged >= self.public["n"]:
                    continue

                signature = pow(
                    forged,
                    self.private["d"],
                    self.public["n"],
                ).to_bytes(384, "big")

                self.assertFalse(
                    pss_verify(self.public, message, signature)
                )

    def test_pss_rejects_wrong_salt_length(self):
        message = b"SecureVault test"

        for length in (0, 16, 31, 33):
            with self.subTest(salt_length=length):
                signature = self.reference.sign(
                    message,
                    pss_scheme(length),
                    hashes.SHA256(),
                )

                self.assertFalse(
                    pss_verify(self.public, message, signature)
                )