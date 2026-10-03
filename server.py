import os
import time
import uuid
import transport
import accounts
from account_store import AccountStore
from crypto.formats import (
    pack_str, unpack_str, take_fixed, check_end,
    Document, Share,
)
from account_messages import (
    encode_dict_message, decode_dict_message, peek_type_byte,
    TYPE_REGISTER_REQUEST, TYPE_LOGIN_BEGIN_REQUEST, TYPE_LOGIN_CHALLENGE,
    TYPE_LOGIN_FINISH_REQUEST, TYPE_LOGIN_RESULT, TYPE_SESSION_REQUEST,
    TYPE_SESSION_RESULT, TYPE_ERROR,
)


STORAGE_ROOT = "server_storage"
ACCOUNT_DB_PATH = "server_private/accounts.db"
NOT_FOUND_MARKER = b"\x00NOT_FOUND"

TYPE_DOCUMENT = Document.TYPE
TYPE_SHARE = Share.TYPE
TYPE_GET_REQUEST = 0

account_store = AccountStore(ACCOUNT_DB_PATH)


class GetRequest:
    VERSION = 1
    TYPE = TYPE_GET_REQUEST

    def __init__(self, requester_id: bytes, store: bytes, key: bytes):
        self.requester_id = requester_id
        self.store = store
        self.key = key

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return header + pack_str(self.requester_id) + pack_str(self.store) + pack_str(self.key)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid GetRequest object")
        offset = 2
        requester_id, offset = unpack_str(data, offset)
        store, offset = unpack_str(data, offset)
        key, offset = unpack_str(data, offset)
        check_end(data, offset)
        return cls(requester_id, store, key)


def _store_dir(store: str) -> str:
    path = os.path.join(STORAGE_ROOT, store)
    os.makedirs(path, exist_ok=True)
    return path


def _safe_key(key: str) -> str:
    if not key or "/" in key or "\\" in key or key in (".", ".."):
        raise ValueError("Invalid storage key")
    return key


def store_object(store: str, key: str, payload: bytes) -> None:
    path = os.path.join(_store_dir(store), _safe_key(key) + ".obj")
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp_path, path)


def load_object(store: str, key: str):
    path = os.path.join(_store_dir(store), _safe_key(key) + ".obj")
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def append_object(store: str, recipient_key: str, payload: bytes) -> None:
    path = os.path.join(_store_dir(store), _safe_key(recipient_key))
    os.makedirs(path, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.obj"
    full_path = os.path.join(path, filename)
    tmp_path = full_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp_path, full_path)


def list_objects(store: str, recipient_key: str):
    path = os.path.join(_store_dir(store), _safe_key(recipient_key))
    if not os.path.isdir(path):
        return []
    results = []
    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".obj"):
            continue
        with open(os.path.join(path, fname), "rb") as f:
            results.append(f.read())
    return results


def _reply(reply_to: str, type_byte: int, body: dict):
    if not reply_to:
        return
    payload = encode_dict_message(type_byte, body)
    transport.send_message(reply_to, payload)


def _reply_error(reply_to: str, message: str = "Authentication failed"):
    _reply(reply_to, TYPE_ERROR, {"error": message})


def handle_register(payload: bytes):
    reply_to, body = decode_dict_message(TYPE_REGISTER_REQUEST, payload)
    try:
        user_id = accounts.handle_registration(account_store, body["records"])
        _reply(reply_to, TYPE_SESSION_RESULT, {"registered": True, "user_id": user_id})
    except (KeyError, ValueError):
        _reply_error(reply_to, "Registration failed")


def handle_login_begin(payload: bytes):
    reply_to, body = decode_dict_message(TYPE_LOGIN_BEGIN_REQUEST, payload)
    try:
        challenge = accounts.begin_login(account_store, body["user_id"])
        _reply(reply_to, TYPE_LOGIN_CHALLENGE, challenge)
    except (KeyError, ValueError):
        _reply_error(reply_to)


def handle_login_finish(payload: bytes):
    reply_to, body = decode_dict_message(TYPE_LOGIN_FINISH_REQUEST, payload)
    try:
        result = accounts.finish_login(account_store, body)
        _reply(reply_to, TYPE_LOGIN_RESULT, result)
    except ValueError:
        _reply_error(reply_to)


def handle_session_request(payload: bytes):
    reply_to, body = decode_dict_message(TYPE_SESSION_REQUEST, payload)
    operation = body.get("operation") if isinstance(body, dict) else None

    try:
        if operation == accounts.PASSWORD_CHANGE_CONTEXT_OPERATION:
            result = accounts.handle_password_change_context(account_store, body)
        elif operation == accounts.PASSWORD_CHANGE_OPERATION:
            result = accounts.handle_password_change(account_store, body)
        elif operation == accounts.LOGOUT_OPERATION:
            result = accounts.handle_logout(account_store, body)
        else:
            _reply_error(reply_to, "Malformed object")
            return

        _reply(reply_to, TYPE_SESSION_RESULT, result)
    except ValueError:
        _reply_error(reply_to)


def handle_incoming(payload: bytes) -> None:
    if len(payload) < 2:
        return

    try:
        type_byte = peek_type_byte(payload)

        if type_byte == TYPE_REGISTER_REQUEST:
            handle_register(payload)
        elif type_byte == TYPE_LOGIN_BEGIN_REQUEST:
            handle_login_begin(payload)
        elif type_byte == TYPE_LOGIN_FINISH_REQUEST:
            handle_login_finish(payload)
        elif type_byte == TYPE_SESSION_REQUEST:
            handle_session_request(payload)
        elif type_byte == TYPE_DOCUMENT:
            doc = Document.from_bytes(payload)
            store_object("documents", doc.document_id.hex(), payload)
        elif type_byte == TYPE_SHARE:
            share = Share.from_bytes(payload)
            append_object("shares", share.recipient_id.decode(), payload)
        elif type_byte == TYPE_GET_REQUEST:
            _handle_get_request(payload)
    except Exception as e:
        import traceback
        print("SERVER ERROR:", repr(e))
        traceback.print_exc()


def _handle_get_request(payload: bytes) -> None:
    req = GetRequest.from_bytes(payload)
    requester_id = req.requester_id.decode()
    store = req.store.decode()
    key = req.key.decode() if req.key else ""

    if store == "shares":
        results = list_objects("shares", requester_id)
        response = b"".join(pack_str(r) for r in results)
        transport.send_message(requester_id, response if results else NOT_FOUND_MARKER)
        return

    if store == "public_keys":
        result = account_store.get("public_key", key.encode())
        if result is None:
            transport.send_message(requester_id, NOT_FOUND_MARKER)
        else:
            transport.send_message(requester_id, result)
        return

    result = load_object(store, key)
    if result is None:
        transport.send_message(requester_id, NOT_FOUND_MARKER)
    else:
        transport.send_message(requester_id, result)

def run_once() -> int:
    messages = transport.poll_messages(transport.SERVER_INBOX)
    for filename, payload in messages:
        handle_incoming(payload)
        transport.consume_message(transport.SERVER_INBOX, filename)
    return len(messages)


def run_forever(poll_interval: float = 0.5):
    print(f"Server running. Watching '{transport.SHARED_ROOT}/{transport.SERVER_INBOX}' for requests...")
    try:
        while True:
            processed = run_once()
            if processed:
                print(f"Processed {processed} message(s)")
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    run_forever()
