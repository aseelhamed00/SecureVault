import secrets
import sqlite3
from pathlib import Path

KINDS = ("public_key", "wrapped_private_key", "credential")


class AccountStore:
    

    def __init__(self, path):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS records ("
                "user_id BLOB NOT NULL, kind TEXT NOT NULL, value BLOB NOT NULL, "
                "PRIMARY KEY (user_id, kind))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata ("
                "name TEXT PRIMARY KEY, value BLOB NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS login_challenges ("
                "challenge_id BLOB PRIMARY KEY, "
                "user_id BLOB NOT NULL, "
                "challenge BLOB NOT NULL, "
                "salt BLOB NOT NULL, "
                "argon2_params BLOB NOT NULL, "
                "expires_at INTEGER NOT NULL, "
                "is_real INTEGER NOT NULL, "
                "used INTEGER NOT NULL DEFAULT 0)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sessions ("
                "session_id BLOB PRIMARY KEY, "
                "user_id BLOB NOT NULL, "
                "expires_at INTEGER NOT NULL, "
                "invalidated INTEGER NOT NULL DEFAULT 0)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS session_requests ("
                "session_id BLOB NOT NULL, "
                "request_id BLOB NOT NULL, "
                "PRIMARY KEY (session_id, request_id))"
            )
        finally:
            connection.close()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _checkpoint(self, stage):
        """Registration test hook: 0 before writes, 1..3 after writes, 4 after commit."""

    def _password_checkpoint(self, stage):
        """Password-change test hook: 0 before writes, 1..3 after writes, 4 after commit."""

    def create_account(self, user_id, records):
        if not isinstance(user_id, bytes) or not user_id:
            raise ValueError("Invalid user ID")
        if set(records) != set(KINDS) or any(not isinstance(v, bytes) for v in records.values()):
            raise ValueError("Invalid account records")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM records WHERE user_id=?", (user_id,)).fetchone():
                raise ValueError("Account already exists")
            self._checkpoint(0)
            for stage, kind in enumerate(KINDS, 1):
                connection.execute(
                    "INSERT INTO records VALUES (?, ?, ?)",
                    (user_id, kind, records[kind]),
                )
                self._checkpoint(stage)
            connection.commit()
            self._checkpoint(4)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def get_account(self, user_id):
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT kind, value FROM records WHERE user_id=?", (user_id,)
            ).fetchall()
        finally:
            connection.close()
        if not rows:
            return None
        records = dict(rows)
        if set(records) != set(KINDS):
            raise ValueError("Incomplete account storage")
        return records

    def get(self, kind, user_id):
        records = self.get_account(user_id)
        return None if records is None else records.get(kind)

    def get_or_create_server_secret(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM metadata WHERE name='login_dummy_secret'"
            ).fetchone()
            if row is None:
                value = secrets.token_bytes(32)
                connection.execute(
                    "INSERT INTO metadata(name, value) VALUES (?, ?)",
                    ("login_dummy_secret", value),
                )
            else:
                value = row[0]
            connection.commit()
            return bytes(value)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def save_login_challenge(
        self,
        challenge_id,
        user_id,
        challenge,
        salt,
        argon2_params,
        expires_at,
        is_real,
    ):
        values = (challenge_id, user_id, challenge, salt, argon2_params)
        if any(not isinstance(value, bytes) for value in values):
            raise ValueError("Invalid login challenge")
        if len(challenge_id) != 16 or len(challenge) != 32 or len(salt) != 16:
            raise ValueError("Invalid login challenge")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("Invalid login challenge")
        if type(is_real) is not bool:
            raise ValueError("Invalid login challenge")

        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO login_challenges("
                "challenge_id, user_id, challenge, salt, argon2_params, "
                "expires_at, is_real, used"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    challenge_id,
                    user_id,
                    challenge,
                    salt,
                    argon2_params,
                    expires_at,
                    int(is_real),
                ),
            )
        finally:
            connection.close()

    def consume_login_challenge(self, challenge_id):
        if not isinstance(challenge_id, bytes) or len(challenge_id) != 16:
            return None

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT user_id, challenge, salt, argon2_params, expires_at, is_real "
                "FROM login_challenges "
                "WHERE challenge_id=? AND used=0",
                (challenge_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                return None

            connection.execute(
                "UPDATE login_challenges SET used=1 "
                "WHERE challenge_id=? AND used=0",
                (challenge_id,),
            )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

        user_id, challenge, salt, argon2_params, expires_at, is_real = row
        return {
            "challenge_id": challenge_id,
            "user_id": bytes(user_id),
            "challenge": bytes(challenge),
            "salt": bytes(salt),
            "argon2_params": bytes(argon2_params),
            "expires_at": int(expires_at),
            "is_real": bool(is_real),
        }
    def save_session(self, session_id, user_id, expires_at):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise ValueError("Invalid session")
        if not isinstance(user_id, bytes) or not user_id:
            raise ValueError("Invalid session")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("Invalid session")

        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO sessions(session_id, user_id, expires_at, invalidated) "
                "VALUES (?, ?, ?, 0)",
                (session_id, user_id, expires_at),
            )
        finally:
            connection.close()

    def get_session(self, session_id):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT user_id, expires_at, invalidated FROM sessions "
                "WHERE session_id=?",
                (session_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        user_id, expires_at, invalidated = row
        return {
            "session_id": session_id,
            "user_id": bytes(user_id),
            "expires_at": int(expires_at),
            "invalidated": bool(invalidated),
        }

    def invalidate_session(self, session_id):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE sessions SET invalidated=1 "
                "WHERE session_id=? AND invalidated=0",
                (session_id,),
            )
            changed = cursor.rowcount == 1
            connection.commit()
            return changed
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def claim_session_request(self, session_id, request_id, now):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            return False
        if not isinstance(request_id, bytes) or len(request_id) != 16:
            return False
        if not isinstance(now, int) or isinstance(now, bool):
            return False

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT expires_at, invalidated FROM sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                return False

            expires_at, invalidated = row
            if bool(invalidated) or now >= int(expires_at):
                connection.rollback()
                return False

            try:
                connection.execute(
                    "INSERT INTO session_requests(session_id, request_id) VALUES (?, ?)",
                    (session_id, request_id),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False

            connection.commit()
            return True
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def update_password_records(
        self,
        user_id,
        expected_credential,
        expected_wrapped_private_key,
        new_credential,
        new_wrapped_private_key,
    ):
        
        values = (
            user_id,
            expected_credential,
            expected_wrapped_private_key,
            new_credential,
            new_wrapped_private_key,
        )
        if any(not isinstance(value, bytes) for value in values):
            raise ValueError("Invalid password update")
        if not user_id or not new_credential or not new_wrapped_private_key:
            raise ValueError("Invalid password update")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT kind, value FROM records "
                "WHERE user_id=? AND kind IN ('credential', 'wrapped_private_key')",
                (user_id,),
            ).fetchall()
            current = dict(rows)
            if (
                current.get("credential") != expected_credential
                or current.get("wrapped_private_key") != expected_wrapped_private_key
            ):
                raise ValueError("Account changed")

            self._password_checkpoint(0)

            cursor = connection.execute(
                "UPDATE records SET value=? WHERE user_id=? AND kind='credential'",
                (new_credential, user_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Account changed")
            self._password_checkpoint(1)

            cursor = connection.execute(
                "UPDATE records SET value=? "
                "WHERE user_id=? AND kind='wrapped_private_key'",
                (new_wrapped_private_key, user_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Account changed")
            self._password_checkpoint(2)

            connection.execute(
                "UPDATE sessions SET invalidated=1 WHERE user_id=?",
                (user_id,),
            )
            self._password_checkpoint(3)

            connection.commit()
            self._password_checkpoint(4)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

