import unittest
from unittest.mock import patch

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from accounts import (
    CREDENTIAL,
    PUBLIC_KEY,
    WRAPPED_PRIVATE_KEY,
    account_exists,
    credential_verifier,
    decode_argon2_params,
    derive_password_values,
    encode_argon2_params,
    LOGIN_CHALLENGE_TTL,
    SESSION_TTL,
    begin_login,
    change_password,
    finish_login,
    handle_password_change,
    handle_password_change_context,
    handle_registration,
    invalidate_session,
    login,
    make_login_response,
    make_password_change_context,
    make_session_request,
    prepare_password_change,
    public_key_fingerprint,
    validate_session,
    validate_session_request,
    register,
    register_account,
)
from crypto.formats import Credential, PublicKey, WrappedPrivateKey
from crypto.sha256 import sha256
from private_keys import unwrap_private_keys

PASSWORD = "Test-only-password-123!"

PARAMS = {"memory_cost": 8192, "time_cost": 1, "parallelism": 1,
          "hash_len": 32, "version": 19}


class TestPasswordDerivation(unittest.TestCase):
    def test_derivation_two_users(self):
        alice = derive_password_values(PASSWORD, bytes(range(16)), PARAMS)
        bob = derive_password_values(PASSWORD, bytes(range(16, 32)), PARAMS)
        self.assertNotEqual(alice["salt"], bob["salt"])
        self.assertNotEqual(alice["auth_value"], bob["auth_value"])
        self.assertNotEqual(alice["wrap_key"], bob["wrap_key"])

    def test_derivation_repeat(self):
        salt = bytes(range(16))
        self.assertEqual(derive_password_values(PASSWORD, salt, PARAMS),
                         derive_password_values(PASSWORD, salt, PARAMS))

    def test_derivation_fresh_salt(self):
        first = derive_password_values(PASSWORD, params=PARAMS)
        second = derive_password_values(PASSWORD, params=PARAMS)
        self.assertEqual(len(first["salt"]), 16)
        self.assertEqual(len(second["salt"]), 16)
        self.assertNotEqual(first["salt"], second["salt"])

    def test_derivation_separate_values(self):
        result = derive_password_values(PASSWORD, params=PARAMS)
        self.assertEqual(len(result["auth_value"]), 32)
        self.assertEqual(len(result["wrap_key"]), 32)
        self.assertNotEqual(result["auth_value"], result["wrap_key"])
        self.assertEqual(result["argon2_params"], PARAMS)
        self.assertEqual(set(result), {"salt", "argon2_params", "auth_value", "wrap_key"})

    def test_derivation_reference(self):
        salt = bytes(range(16))
        result = derive_password_values(PASSWORD, salt, PARAMS)
        material = hash_secret_raw(secret=PASSWORD.encode("utf-8"), salt=salt,
                                   type=Type.ID, **PARAMS)
        for field, label in (("auth_value", b"securevault:v1:auth"),
                             ("wrap_key", b"securevault:v1:wrap")):
            expected = HKDF(algorithm=hashes.SHA256(), length=32,
                            salt=b"", info=label).derive(material)
            self.assertEqual(result[field], expected)

    def test_derivation_changed_password(self):
        salt = bytes(range(16))
        first = derive_password_values(PASSWORD, salt, PARAMS)
        second = derive_password_values(PASSWORD + "!", salt, PARAMS)
        self.assertNotEqual(first["auth_value"], second["auth_value"])
        self.assertNotEqual(first["wrap_key"], second["wrap_key"])

    def test_derivation_invalid_inputs(self):
        for salt in (b"", bytes(15), bytes(17), "x" * 16):
            with self.assertRaises(ValueError):
                derive_password_values(PASSWORD, salt, PARAMS)
        with self.assertRaises(TypeError):
            derive_password_values(b"password", params=PARAMS)
        for field, value in (("time_cost", 0), ("time_cost", True),
                             ("memory_cost", 262145), ("parallelism", 0),
                             ("hash_len", 16), ("version", 16)):
            bad = dict(PARAMS)
            bad[field] = value
            with self.assertRaises(ValueError):
                derive_password_values(PASSWORD, params=bad)

    def test_derivation_selected_config(self):
        with patch("accounts.load_password_parameters", return_value=PARAMS):
            result = derive_password_values(PASSWORD, bytes(range(16)))
        self.assertEqual(result, derive_password_values(PASSWORD, bytes(range(16)), PARAMS))


class TestRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layla = register("layla", PASSWORD, PARAMS)
        cls.omar = register("omar", PASSWORD, PARAMS)

    def setUp(self):
        import tempfile
        from pathlib import Path
        from account_store import AccountStore
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "accounts.db"
        self.store = AccountStore(self.path)

    def test_registration_two_users(self):
        for account in (self.layla, self.omar):
            handle_registration(self.store, account["records"])
            self.assertTrue(account_exists(self.store, account["user_id"]))
            recovered = unwrap_private_keys(account["user_id"], account["wrap_key"],
                self.store.get(WRAPPED_PRIVATE_KEY, account["user_id"]))
            self.assertEqual(recovered, account["bundle"])
        a = Credential.from_bytes(self.store.get(CREDENTIAL, b"layla"))
        b = Credential.from_bytes(self.store.get(CREDENTIAL, b"omar"))
        self.assertNotEqual(a.salt, b.salt)
        self.assertNotEqual(a.auth_value, b.auth_value)
        self.assertEqual(a.auth_value, credential_verifier(self.layla["auth_value"]))
        self.assertEqual(decode_argon2_params(a.argon2_params), PARAMS)

    def test_registration_public_records_and_no_secrets(self):
        handle_registration(self.store, self.layla["records"])
        records = self.store.get_account(b"layla")
        self.assertEqual(records, self.layla["records"])
        public = PublicKey.from_bytes(records[PUBLIC_KEY])
        self.assertEqual(public.p256_public_key, self.layla["bundle"]["p256_public"])
        self.assertEqual(public.rsa_public_exponent, b"\x01\x00\x01")
        self.assertEqual(self.layla["fingerprint"], sha256(records[PUBLIC_KEY]))
        published = b"".join(records.values()) + self.path.read_bytes()
        private = self.layla["bundle"]["rsa_private"]
        for secret in (PASSWORD.encode(), self.layla["wrap_key"], self.layla["auth_value"],
                       self.layla["bundle"]["p256_private"],
                       private["d"].to_bytes(384, "big"), private["p"].to_bytes(192, "big"),
                       private["q"].to_bytes(192, "big")):
            self.assertNotIn(secret, published)

    def test_registration_duplicate_rejected(self):
        handle_registration(self.store, self.layla["records"])
        before = self.store.get_account(b"layla")
        with self.assertRaisesRegex(ValueError, "already exists"):
            handle_registration(self.store, self.layla["records"])
        self.assertEqual(self.store.get_account(b"layla"), before)

    def test_registration_malformed_records(self):
        for kind in self.layla["records"]:
            for blob in (b"", self.layla["records"][kind][:-1], self.layla["records"][kind]+b"x"):
                broken = dict(self.layla["records"], **{kind: blob})
                with self.subTest(kind=kind, length=len(blob)):
                    with self.assertRaises(ValueError):
                        handle_registration(self.store, broken)
        self.assertFalse(account_exists(self.store, "layla"))

    def test_registration_invalid_public_keys(self):
        for field, value in (("p256_public_key", b"\x04"+bytes(64)),
                             ("rsa_public_exponent", bytes(3)),
                             ("rsa_modulus", bytes(384))):
            pub = PublicKey.from_bytes(self.layla["records"][PUBLIC_KEY])
            setattr(pub, field, value)
            broken = dict(self.layla["records"], public_key=pub.to_bytes())
            with self.subTest(field=field), self.assertRaises(ValueError):
                handle_registration(self.store, broken)

    def test_registration_missing_and_mismatched_records(self):
        broken = dict(self.layla["records"])
        del broken[PUBLIC_KEY]
        with self.assertRaises(ValueError):
            handle_registration(self.store, broken)
        broken[PUBLIC_KEY] = self.omar["records"][PUBLIC_KEY]
        with self.assertRaises(ValueError):
            handle_registration(self.store, broken)

    def test_registration_bad_parameters(self):
        record = Credential.from_bytes(self.layla["records"][CREDENTIAL])
        record.argon2_params = bytes(20)
        broken = dict(self.layla["records"], credential=record.to_bytes())
        with self.assertRaises(ValueError):
            handle_registration(self.store, broken)

    def test_registration_failure_after_each_write(self):
        from account_store import AccountStore
        for stage in range(4):
            def fail(current):
                if current == stage:
                    raise OSError("interrupted after write")
            with self.subTest(stage=stage):
                with patch.object(self.store, "_checkpoint", side_effect=fail):
                    with self.assertRaises(OSError):
                        handle_registration(self.store, self.layla["records"])
                reopened = AccountStore(self.path)
                self.assertIsNone(reopened.get_account(b"layla"))
        handle_registration(self.store, self.layla["records"])
        self.assertEqual(self.store.get_account(b"layla"), self.layla["records"])

    def test_registration_error_after_commit_keeps_complete_account(self):
        def fail(stage):
            if stage == 4:
                raise OSError("lost response after commit")
        with patch.object(self.store, "_checkpoint", side_effect=fail):
            with self.assertRaises(OSError):
                handle_registration(self.store, self.layla["records"])
        self.assertEqual(self.store.get_account(b"layla"), self.layla["records"])
        with self.assertRaisesRegex(ValueError, "already exists"):
            handle_registration(self.store, self.layla["records"])

    def test_registration_concurrent_duplicate(self):
        from concurrent.futures import ThreadPoolExecutor
        from account_store import AccountStore
        def attempt(_):
            try:
                handle_registration(AccountStore(self.path), self.layla["records"])
                return "created"
            except ValueError:
                return "duplicate"
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(attempt, range(2))), ["created", "duplicate"])
        self.assertEqual(self.store.get_account(b"layla"), self.layla["records"])

    def test_registration_process_exit_and_restart(self):
        import json
        import subprocess
        import sys
        from account_store import AccountStore
        request = self.path.parent / "records.json"
        request.write_text(json.dumps({k: v.hex() for k, v in self.layla["records"].items()}))
        code = """
import json, os, sys
from account_store import AccountStore
from accounts import handle_registration
class CrashStore(AccountStore):
    def _checkpoint(self, stage):
        if stage == int(sys.argv[3]):
            os._exit(71)
records = {k: bytes.fromhex(v) for k, v in json.load(open(sys.argv[2])).items()}
handle_registration(CrashStore(sys.argv[1]), records)
"""
        for stage in range(5):
            path = self.path.parent / ("crash-%s.db" % stage)
            with self.subTest(stage=stage):
                run = subprocess.run([sys.executable, "-c", code, str(path), str(request), str(stage)],
                                     capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 71, run.stderr)
                store = AccountStore(path)
                if stage < 4:
                    self.assertIsNone(store.get_account(b"layla"))
                    handle_registration(store, self.layla["records"])
                self.assertEqual(store.get_account(b"layla"), self.layla["records"])

    def test_registration_handler_wrapper(self):
        with patch("accounts.rsa_keygen", return_value=(self.layla["bundle"]["rsa_private"],
                                                       self.layla["bundle"]["rsa_public"])):
            account = register_account(self.store, "sara", PASSWORD, PARAMS)
        self.assertTrue(account_exists(self.store, "sara"))
        self.assertEqual(unwrap_private_keys("sara", account["wrap_key"],
            self.store.get(WRAPPED_PRIVATE_KEY, b"sara")), account["bundle"])


class TestLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.account = register("layla", PASSWORD, PARAMS)

    def setUp(self):
        import tempfile
        from pathlib import Path
        from account_store import AccountStore

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "accounts.db"
        self.store = AccountStore(self.path)
        handle_registration(self.store, self.account["records"])

    def test_login_correct_password_recovers_keys(self):
        result = login(self.store, "layla", PASSWORD)

        self.assertEqual(result["user_id"], b"layla")
        self.assertEqual(result["bundle"], self.account["bundle"])
        self.assertEqual(result["wrap_key"], self.account["wrap_key"])
        self.assertEqual(result["fingerprint"], self.account["fingerprint"])
        self.assertEqual(result["session"]["user_id"], b"layla")
        self.assertEqual(len(result["session"]["session_id"]), 16)
        self.assertEqual(len(result["session"]["session_key"]), 32)

    def test_login_wrong_password_and_unknown_user_same_failure(self):
        failures = []

        with patch("accounts.load_password_parameters", return_value=PARAMS):
            for user_id, password in (
                ("layla", PASSWORD + "!"),
                ("unknown-user", PASSWORD),
            ):
                with self.subTest(user_id=user_id):
                    with self.assertRaises(ValueError) as caught:
                        login(self.store, user_id, password)
                    failures.append(str(caught.exception))

        self.assertEqual(failures, ["Authentication failed", "Authentication failed"])

    def test_login_response_does_not_contain_private_material(self):
        challenge = begin_login(self.store, "layla")
        response, wrap_key = make_login_response(PASSWORD, challenge)

        self.assertEqual(set(response), {"challenge_id", "response"})
        self.assertNotIn(wrap_key, response.values())
        self.assertNotIn(self.account["bundle"]["p256_private"], response.values())

    def test_login_altered_challenge_fails(self):
        challenge = begin_login(self.store, "layla")
        altered = dict(challenge)
        changed = bytearray(altered["challenge"])
        changed[0] ^= 0x01
        altered["challenge"] = bytes(changed)

        response, _ = make_login_response(PASSWORD, altered)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(self.store, response)

    def test_login_altered_response_fails(self):
        challenge = begin_login(self.store, "layla")
        response, _ = make_login_response(PASSWORD, challenge)

        broken = dict(response)
        tag = bytearray(broken["response"])
        tag[-1] ^= 0x01
        broken["response"] = bytes(tag)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(self.store, broken)

    def test_login_expired_challenge_fails(self):
        start = 1000
        challenge = begin_login(self.store, "layla", now=start)
        response, _ = make_login_response(PASSWORD, challenge)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(
                self.store,
                response,
                now=start + LOGIN_CHALLENGE_TTL + 1,
            )

    def test_login_challenge_is_one_time(self):
        challenge = begin_login(self.store, "layla")
        response, _ = make_login_response(PASSWORD, challenge)

        accepted = finish_login(self.store, response)
        self.assertEqual(accepted["user_id"], b"layla")

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(self.store, response)

    def test_login_wrong_response_consumes_challenge(self):
        challenge = begin_login(self.store, "layla")
        response, _ = make_login_response(PASSWORD + "!", challenge)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(self.store, response)

        correct, _ = make_login_response(PASSWORD, challenge)
        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            finish_login(self.store, correct)

    def test_login_unknown_challenge_has_same_public_shape(self):
        with patch("accounts.load_password_parameters", return_value=PARAMS):
            known = begin_login(self.store, "layla")
            unknown = begin_login(self.store, "nobody")

        self.assertEqual(set(known), set(unknown))
        self.assertEqual(len(known["salt"]), len(unknown["salt"]))
        self.assertEqual(len(known["argon2_params"]), len(unknown["argon2_params"]))
        self.assertEqual(len(known["challenge_id"]), len(unknown["challenge_id"]))
        self.assertEqual(len(known["challenge"]), len(unknown["challenge"]))

    def test_login_unknown_dummy_salt_is_stable_but_not_publicly_predictable(self):
        with patch("accounts.load_password_parameters", return_value=PARAMS):
            first = begin_login(self.store, "missing-user")
            second = begin_login(self.store, "missing-user")
            other = begin_login(self.store, "other-missing-user")

        self.assertEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["salt"], other["salt"])

    def test_login_timing_wrong_password_vs_unknown_user(self):
        import statistics
        import time

        known_times = []
        unknown_times = []

        with patch("accounts.load_password_parameters", return_value=PARAMS):
            for round_number in range(8):
                order = (
                    (("layla", PASSWORD + "!", known_times),
                     ("missing-user", PASSWORD, unknown_times))
                    if round_number % 2 == 0
                    else
                    (("missing-user", PASSWORD, unknown_times),
                     ("layla", PASSWORD + "!", known_times))
                )

                for user_id, password, bucket in order:
                    start = time.perf_counter()
                    with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                        login(self.store, user_id, password)
                    bucket.append(time.perf_counter() - start)

        known_median = statistics.median(known_times)
        unknown_median = statistics.median(unknown_times)
        difference = abs(known_median - unknown_median)

        allowed = max(0.015, 0.25 * max(known_median, unknown_median))
        self.assertLessEqual(
            difference,
            allowed,
            msg=(
                f"timing medians too far apart: known={known_median:.6f}s, "
                f"unknown={unknown_median:.6f}s, allowed={allowed:.6f}s"
            ),
        )

class TestSessionHandling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layla = register("layla", PASSWORD, PARAMS)
        cls.omar = register("omar", PASSWORD + "-omar", PARAMS)

    def setUp(self):
        import tempfile
        from pathlib import Path
        from account_store import AccountStore

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "accounts.db"
        self.store = AccountStore(self.path)
        handle_registration(self.store, self.layla["records"])
        handle_registration(self.store, self.omar["records"])

    def test_session_created_after_valid_login(self):
        result = login(self.store, "layla", PASSWORD, now=1000)
        session = result["session"]

        self.assertEqual(session["user_id"], b"layla")
        self.assertEqual(len(session["session_id"]), 16)
        self.assertEqual(len(session["session_key"]), 32)
        self.assertEqual(session["expires_at"], 1000 + SESSION_TTL)

        checked = validate_session(self.store, session["session_id"], now=1001)
        self.assertEqual(checked["user_id"], b"layla")
        self.assertEqual(checked["session_id"], session["session_id"])

    def test_session_missing_and_altered_rejected(self):
        result = login(self.store, "layla", PASSWORD)
        session_id = result["session"]["session_id"]

        missing = b"\x00" * 16
        if missing == session_id:
            missing = b"\x01" * 16

        altered = bytearray(session_id)
        altered[0] ^= 1

        for candidate in (missing, bytes(altered), b"", bytes(15), bytes(17)):
            with self.subTest(length=len(candidate)):
                with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                    validate_session(self.store, candidate)

    def test_session_expired_rejected(self):
        start = 1000
        result = login(self.store, "layla", PASSWORD, now=start)
        session_id = result["session"]["session_id"]

        self.assertEqual(
            validate_session(self.store, session_id, now=start + SESSION_TTL - 1)["user_id"],
            b"layla",
        )

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session(self.store, session_id, now=start + SESSION_TTL)

    def test_session_invalidation(self):
        result = login(self.store, "layla", PASSWORD)
        session_id = result["session"]["session_id"]

        self.assertTrue(invalidate_session(self.store, session_id))

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session(self.store, session_id)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            invalidate_session(self.store, session_id)

    def test_session_valid_request_keeps_bound_identity(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(
            result["session"],
            "list-documents",
            b"page=1",
        )

        accepted = validate_session_request(self.store, request)

        self.assertEqual(accepted["user_id"], b"layla")
        self.assertEqual(accepted["operation"], b"list-documents")
        self.assertEqual(accepted["payload"], b"page=1")
        self.assertEqual(accepted["session_id"], result["session"]["session_id"])

    def test_session_claiming_another_identity_is_rejected(self):
        result = login(self.store, "layla", PASSWORD)

        request = make_session_request(
            result["session"],
            "read-private-area",
            b"",
            user_id="omar",
        )

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, request)

    def test_session_edited_identity_field_is_rejected(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(result["session"], "list-documents")
        broken = dict(request)
        broken["user_id"] = b"omar"

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, broken)

    def test_session_altered_request_rejected(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(result["session"], "list-documents", b"original")

        for field, value in (
            ("payload", b"changed"),
            ("operation", b"delete-account"),
        ):
            broken = dict(request)
            broken[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                    validate_session_request(self.store, broken)

        broken = dict(request)
        tag = bytearray(broken["tag"])
        tag[0] ^= 1
        broken["tag"] = bytes(tag)
        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, broken)

    def test_session_captured_request_replay_rejected(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(
            result["session"],
            "download",
            b"document-17",
            request_id=bytes(range(16)),
        )

        first = validate_session_request(self.store, request)
        self.assertEqual(first["user_id"], b"layla")

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, request)

    def test_session_replay_state_survives_store_restart(self):
        from account_store import AccountStore

        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(
            result["session"],
            "download",
            b"document-17",
            request_id=b"R" * 16,
        )

        self.assertEqual(
            validate_session_request(self.store, request)["user_id"],
            b"layla",
        )

        reopened = AccountStore(self.path)
        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(reopened, request)

    def test_session_failed_tamper_does_not_consume_request_id(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(
            result["session"],
            "download",
            b"document-17",
            request_id=bytes(range(16)),
        )
        broken = dict(request)
        broken["payload"] = b"document-18"

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, broken)

        accepted = validate_session_request(self.store, request)
        self.assertEqual(accepted["user_id"], b"layla")

    def test_session_invalidated_request_rejected(self):
        result = login(self.store, "layla", PASSWORD)
        request = make_session_request(result["session"], "list-documents")
        invalidate_session(self.store, result["session"]["session_id"])

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(self.store, request)

    def test_session_expired_request_rejected(self):
        start = 1000
        result = login(self.store, "layla", PASSWORD, now=start)
        request = make_session_request(result["session"], "list-documents")

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            validate_session_request(
                self.store,
                request,
                now=start + SESSION_TTL,
            )

    def test_session_separate_logins_have_separate_keys(self):
        first = login(self.store, "layla", PASSWORD)
        second = login(self.store, "layla", PASSWORD)

        self.assertNotEqual(first["session"]["session_id"], second["session"]["session_id"])
        self.assertNotEqual(first["session"]["session_key"], second["session"]["session_key"])

class TestPasswordChange(unittest.TestCase):
    NEW_PASSWORD = "New-test-password-456!"

    @classmethod
    def setUpClass(cls):
        cls.account = register("layla", PASSWORD, PARAMS)
        cls.omar = register("omar", PASSWORD + "-omar", PARAMS)

    def setUp(self):
        import tempfile
        from pathlib import Path
        from account_store import AccountStore

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "accounts.db"
        self.store = AccountStore(self.path)
        handle_registration(self.store, self.account["records"])
        handle_registration(self.store, self.omar["records"])

    def test_password_change_success_new_password_only(self):
        before = self.store.get_account(b"layla")
        old_credential = Credential.from_bytes(before[CREDENTIAL])
        first_login = login(self.store, "layla", PASSWORD)

        result = change_password(
            self.store,
            first_login["session"],
            PASSWORD,
            self.NEW_PASSWORD,
            PARAMS,
        )

        self.assertEqual(result["bundle"], self.account["bundle"])
        self.assertTrue(result["session_invalidated"])

        after = self.store.get_account(b"layla")
        new_credential = Credential.from_bytes(after[CREDENTIAL])

        self.assertNotEqual(new_credential.salt, old_credential.salt)
        self.assertEqual(decode_argon2_params(new_credential.argon2_params), PARAMS)
        self.assertNotEqual(after[CREDENTIAL], before[CREDENTIAL])
        self.assertNotEqual(after[WRAPPED_PRIVATE_KEY], before[WRAPPED_PRIVATE_KEY])

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            login(self.store, "layla", PASSWORD)

        fresh = login(self.store, "layla", self.NEW_PASSWORD)
        self.assertEqual(fresh["bundle"], self.account["bundle"])

    def test_password_change_preserves_identity_keys_and_public_record(self):
        before = self.store.get_account(b"layla")
        original_public = before[PUBLIC_KEY]
        original_fingerprint = public_key_fingerprint(original_public)
        signed_in = login(self.store, "layla", PASSWORD)

        changed = change_password(
            self.store,
            signed_in["session"],
            PASSWORD,
            self.NEW_PASSWORD,
            PARAMS,
        )
        after = self.store.get_account(b"layla")
        fresh = login(self.store, "layla", self.NEW_PASSWORD)

        self.assertEqual(after[PUBLIC_KEY], original_public)
        self.assertEqual(changed["fingerprint"], original_fingerprint)
        self.assertEqual(fresh["fingerprint"], original_fingerprint)
        self.assertEqual(changed["bundle"], self.account["bundle"])
        self.assertEqual(fresh["bundle"], self.account["bundle"])

    def test_password_change_context_excludes_stored_verifier(self):
        records = self.store.get_account(b"layla")
        credential = Credential.from_bytes(records[CREDENTIAL])
        signed_in = login(self.store, "layla", PASSWORD)
        request = make_session_request(
            signed_in["session"], "password-change-context"
        )
        context = handle_password_change_context(self.store, request)

        self.assertNotIn(CREDENTIAL, context)
        self.assertNotIn(credential.auth_value, context.values())
        self.assertEqual(context["salt"], credential.salt)
        self.assertEqual(context["argon2_params"], credential.argon2_params)
        self.assertEqual(context[PUBLIC_KEY], records[PUBLIC_KEY])
        self.assertEqual(context[WRAPPED_PRIVATE_KEY], records[WRAPPED_PRIVATE_KEY])

    def test_password_change_wrong_old_password_changes_nothing(self):
        before = self.store.get_account(b"layla")
        signed_in = login(self.store, "layla", PASSWORD)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            change_password(
                self.store,
                signed_in["session"],
                PASSWORD + "!",
                self.NEW_PASSWORD,
                PARAMS,
            )

        self.assertEqual(self.store.get_account(b"layla"), before)
        self.assertEqual(
            validate_session(self.store, signed_in["session"]["session_id"])["user_id"],
            b"layla",
        )
        self.assertEqual(login(self.store, "layla", PASSWORD)["bundle"], self.account["bundle"])

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            login(self.store, "layla", self.NEW_PASSWORD)

    def test_password_change_invalidates_all_existing_sessions(self):
        first = login(self.store, "layla", PASSWORD)
        second = login(self.store, "layla", PASSWORD)

        change_password(
            self.store,
            first["session"],
            PASSWORD,
            self.NEW_PASSWORD,
            PARAMS,
        )

        for session in (first["session"], second["session"]):
            with self.subTest(session=session["session_id"].hex()):
                with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                    validate_session(self.store, session["session_id"])

        fresh = login(self.store, "layla", self.NEW_PASSWORD)
        self.assertEqual(validate_session(
            self.store, fresh["session"]["session_id"]
        )["user_id"], b"layla")

    def test_password_change_requires_session_bound_to_same_user(self):
        layla = login(self.store, "layla", PASSWORD)
        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            prepare_password_change(
                "omar",
                PASSWORD + "-omar",
                self.NEW_PASSWORD,
                make_password_change_context(self.store.get_account(b"omar"), b"omar"),
                layla["session"],
                PARAMS,
            )

        self.assertEqual(login(self.store, "omar", PASSWORD + "-omar")["user_id"], b"omar")

    def test_password_change_rejects_bad_old_password_proof(self):
        signed_in = login(self.store, "layla", PASSWORD)
        records = self.store.get_account(b"layla")
        request, _ = prepare_password_change(
            "layla",
            PASSWORD,
            self.NEW_PASSWORD,
            make_password_change_context(records, b"layla"),
            signed_in["session"],
            PARAMS,
        )

        broken_payload = bytearray(request["payload"])
        broken_payload[-1] ^= 1
        broken_request = make_session_request(
            signed_in["session"],
            "change-password",
            bytes(broken_payload),
        )

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            handle_password_change(self.store, broken_request)

        self.assertEqual(self.store.get_account(b"layla"), records)
        self.assertEqual(login(self.store, "layla", PASSWORD)["bundle"], self.account["bundle"])

    def test_password_change_rejects_tampered_new_records(self):
        signed_in = login(self.store, "layla", PASSWORD)
        records = self.store.get_account(b"layla")
        request, _ = prepare_password_change(
            "layla",
            PASSWORD,
            self.NEW_PASSWORD,
            make_password_change_context(records, b"layla"),
            signed_in["session"],
            PARAMS,
        )

        # The session MAC binds the payload.  Editing the payload without the
        # session key is rejected before any account state is changed.
        broken = dict(request)
        payload = bytearray(broken["payload"])
        payload[10] ^= 1
        broken["payload"] = bytes(payload)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            handle_password_change(self.store, broken)

        self.assertEqual(self.store.get_account(b"layla"), records)

    def test_password_change_interruption_is_old_or_new_state(self):
        from account_store import AccountStore

        for stage in range(5):
            with self.subTest(stage=stage):
                path = self.path.parent / f"password-change-{stage}.db"
                store = AccountStore(path)
                handle_registration(store, self.account["records"])
                signed_in = login(store, "layla", PASSWORD)
                before = store.get_account(b"layla")
                request, local = prepare_password_change(
                    "layla",
                    PASSWORD,
                    self.NEW_PASSWORD,
                    make_password_change_context(before, b"layla"),
                    signed_in["session"],
                    PARAMS,
                )

                def fail(current):
                    if current == stage:
                        raise OSError("simulated interruption")

                with patch.object(store, "_password_checkpoint", side_effect=fail):
                    with self.assertRaises(OSError):
                        handle_password_change(store, request)

                reopened = AccountStore(path)
                after = reopened.get_account(b"layla")

                if stage < 4:
                    self.assertEqual(after, before)
                    recovered = login(reopened, "layla", PASSWORD)
                    self.assertEqual(recovered["bundle"], self.account["bundle"])
                    with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                        login(reopened, "layla", self.NEW_PASSWORD)
                else:
                    self.assertNotEqual(after[CREDENTIAL], before[CREDENTIAL])
                    self.assertNotEqual(after[WRAPPED_PRIVATE_KEY], before[WRAPPED_PRIVATE_KEY])
                    self.assertEqual(after[PUBLIC_KEY], before[PUBLIC_KEY])
                    recovered = login(reopened, "layla", self.NEW_PASSWORD)
                    self.assertEqual(recovered["bundle"], self.account["bundle"])
                    self.assertEqual(recovered["wrap_key"], local["wrap_key"])
                    with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
                        login(reopened, "layla", PASSWORD)

    def test_password_change_stale_update_cannot_overwrite_new_state(self):
        from account_store import AccountStore

        first = login(self.store, "layla", PASSWORD)
        second = login(self.store, "layla", PASSWORD)
        old_records = self.store.get_account(b"layla")

        first_request, _ = prepare_password_change(
            "layla", PASSWORD, self.NEW_PASSWORD,
            make_password_change_context(old_records, b"layla"), first["session"], PARAMS
        )
        second_request, _ = prepare_password_change(
            "layla", PASSWORD, self.NEW_PASSWORD + "-other",
            make_password_change_context(old_records, b"layla"),
            second["session"], PARAMS
        )

        handle_password_change(self.store, first_request)

        with self.assertRaisesRegex(ValueError, "^Authentication failed$"):
            handle_password_change(self.store, second_request)

        reopened = AccountStore(self.path)
        self.assertEqual(
            login(reopened, "layla", self.NEW_PASSWORD)["bundle"],
            self.account["bundle"],
        )

