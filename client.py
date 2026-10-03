import json
import os
import sys
import time
import secrets

from server import GetRequest
import accounts
import private_keys
import transport
import sharing
import trust
from account_messages import (
    encode_dict_message, decode_dict_message, peek_type_byte,
    TYPE_REGISTER_REQUEST, TYPE_LOGIN_BEGIN_REQUEST, TYPE_LOGIN_CHALLENGE,
    TYPE_LOGIN_FINISH_REQUEST, TYPE_LOGIN_RESULT, TYPE_SESSION_REQUEST,
    TYPE_SESSION_RESULT, TYPE_ERROR,
)
from crypto.aead import aead_encrypt, aead_decrypt, AuthenticationError
from crypto.formats import Document, Share, PublicKey, unpack_str
from freshness import check_freshness, save_freshness_state, load_freshness_state


CLIENT_LOCAL_ROOT = "client_local"


def _client_dir(user_id: str, client_dir=None) -> str:
    if client_dir is None:
        path = os.path.join(CLIENT_LOCAL_ROOT, user_id)
    else:
        path = os.fspath(client_dir)
    os.makedirs(path, exist_ok=True)
    return path


def _session_path(user_id: str, client_dir=None) -> str:
    return os.path.join(_client_dir(user_id, client_dir), "session.json")


def _wait_for_reply(user_id: str, timeout: float = 10.0):
    result = transport.wait_for_message(user_id, timeout=timeout)
    if result is None:
        return None
    filename, payload = result
    try:
        type_byte = peek_type_byte(payload)
        _, body = decode_dict_message(type_byte, payload)
        return type_byte, body
    finally:
        transport.consume_message(user_id, filename)


def _save_local_session(user_id: str, session: dict, bundle: dict, wrap_key: bytes, client_dir=None):
    path = _session_path(user_id, client_dir)
    data = {
        "session_id": session["session_id"].hex(),
        "user_id": session["user_id"].hex(),
        "expires_at": session["expires_at"],
        "session_key": session["session_key"].hex(),
        "wrap_key": wrap_key.hex(),
        "bundle": {
            "p256_private": bundle["p256_private"].hex(),
            "p256_public": bundle["p256_public"].hex(),
            "rsa_private": bundle["rsa_private"],
            "rsa_public": bundle["rsa_public"],
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _load_local_session(user_id: str, client_dir=None):
    path = _session_path(user_id, client_dir)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {
        "session_id": bytes.fromhex(data["session_id"]),
        "user_id": bytes.fromhex(data["user_id"]),
        "expires_at": data["expires_at"],
        "session_key": bytes.fromhex(data["session_key"]),
    }


def _load_wrap_key(user_id: str, client_dir=None):
    path = _session_path(user_id, client_dir)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return bytes.fromhex(data["wrap_key"])


def load_recovered_keys(user_id: str, client_dir=None):
    path = _session_path(user_id, client_dir)
    if not os.path.exists(path):
        return None

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("Invalid local key state")

    try:
        rsa_private = dict(bundle["rsa_private"])
        rsa_public = dict(bundle["rsa_public"])
        recovered = {
            "p256_private": bytes.fromhex(bundle["p256_private"]),
            "p256_public": bytes.fromhex(bundle["p256_public"]),
            "rsa_private": rsa_private,
            "rsa_public": rsa_public,
        }
    except (KeyError, TypeError, ValueError):
        raise ValueError("Invalid local key state") from None

    if set(recovered["rsa_private"]) != {"n", "e", "d", "p", "q"}:
        raise ValueError("Invalid local key state")
    if set(recovered["rsa_public"]) != {"n", "e"}:
        raise ValueError("Invalid local key state")
    if len(recovered["p256_private"]) != 32 or len(recovered["p256_public"]) != 65:
        raise ValueError("Invalid local key state")

    return recovered


def _delete_local_session(user_id: str, client_dir=None):
    path = _session_path(user_id, client_dir)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _send_account_request(user_id: str, type_byte: int, body: dict, timeout: float):
    payload = encode_dict_message(type_byte, body, reply_to=user_id)
    transport.send_message(transport.SERVER_INBOX, payload)
    return _wait_for_reply(user_id, timeout=timeout)


def _document_key_path(user_id: str, client_dir=None) -> str:
    return os.path.join(_client_dir(user_id, client_dir), "document_keys.json")


def _load_document_keys(user_id: str, client_dir=None) -> dict:
    path = _document_key_path(user_id, client_dir)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_document_keys(user_id: str, keys: dict, client_dir=None):
    path = _document_key_path(user_id, client_dir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(keys, f)


def store_document_key_locally(user_id: str, wrap_key: bytes, document_id: bytes, document_key: bytes, client_dir=None):
    nonce = secrets.token_bytes(12)
    aad = bytes([1, 6]) + document_id
    ciphertext, tag = aead_encrypt(wrap_key, nonce, aad, document_key)

    keys = _load_document_keys(user_id, client_dir)
    keys[document_id.hex()] = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }
    _save_document_keys(user_id, keys, client_dir)


def load_document_key_locally(user_id: str, wrap_key: bytes, document_id: bytes, client_dir=None):
    keys = _load_document_keys(user_id, client_dir)
    entry = keys.get(document_id.hex())
    if entry is None:
        return None

    nonce = bytes.fromhex(entry["nonce"])
    ciphertext = bytes.fromhex(entry["ciphertext"])
    tag = bytes.fromhex(entry["tag"])
    aad = bytes([1, 6]) + document_id

    try:
        return aead_decrypt(wrap_key, nonce, aad, ciphertext, tag)
    except AuthenticationError:
        return None


def _trusted_keys_path(user_id: str, client_dir=None) -> str:
    return os.path.join(_client_dir(user_id, client_dir), "trusted_keys.json")


def _load_trusted_keys(user_id: str, client_dir=None) -> dict:
    path = _trusted_keys_path(user_id, client_dir)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {
        uid: {
            "p256_public_key": bytes.fromhex(entry["p256_public_key"]),
            "rsa_public_key": entry["rsa_public_key"],
            "rsa_public_exponent": entry["rsa_public_exponent"],
            "fingerprint": bytes.fromhex(entry["fingerprint"]),
            "verified": entry["verified"],
        }
        for uid, entry in raw.items()
    }


def _save_trusted_keys(user_id: str, trusted_keys: dict, client_dir=None):
    path = _trusted_keys_path(user_id, client_dir)
    raw = {
        uid: {
            "p256_public_key": entry["p256_public_key"].hex(),
            "rsa_public_key": entry["rsa_public_key"],
            "rsa_public_exponent": entry["rsa_public_exponent"],
            "fingerprint": entry["fingerprint"].hex(),
            "verified": entry["verified"],
        }
        for uid, entry in trusted_keys.items()
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f)


def _freshness_path(user_id: str, client_dir=None) -> str:
    return os.path.join(_client_dir(user_id, client_dir), "freshness_state.txt")


def get_and_trust_public_key(requester_id: str, target_user_id: str, client_dir=None, timeout: float = 10.0):
    req = GetRequest(requester_id.encode(), b"public_keys", target_user_id.encode())
    transport.send_message(transport.SERVER_INBOX, req.to_bytes())

    result = transport.wait_for_message(requester_id, timeout=timeout)
    if result is None:
        print("No response from server (timeout)")
        return None
    filename, payload = result
    transport.consume_message(requester_id, filename)

    if payload == b"\x00NOT_FOUND":
        print(f"No public key found for '{target_user_id}'")
        return None

    try:
        pk = PublicKey.from_bytes(payload)
    except ValueError:
        print("Malformed object")
        return None

    rsa_n = int.from_bytes(pk.rsa_modulus, "big")
    rsa_e = int.from_bytes(pk.rsa_public_exponent, "big")

    trusted_keys = _load_trusted_keys(requester_id, client_dir)

    if target_user_id not in trusted_keys:
        trust.trust_first_key(trusted_keys, target_user_id, pk.p256_public_key, rsa_n, rsa_e)
        _save_trusted_keys(requester_id, trusted_keys, client_dir)
        print(f"First contact with '{target_user_id}' -- key trusted on first use (TOFU)")
        print(f"Fingerprint: {trust.get_fingerprint(trusted_keys, target_user_id).hex()}")
    else:
        if not trust.check_trusted_key(trusted_keys, target_user_id, pk.p256_public_key, rsa_n, rsa_e):
            print(f"WARNING: '{target_user_id}'s key has changed since it was trusted. Refusing to proceed.")
            return None

    return pk


def cmd_upload(filepath: str, owner_id: str, client_dir=None):
    wrap_key = _load_wrap_key(owner_id, client_dir)
    if wrap_key is None:
        print("You must be logged in to upload. Run 'login' first.")
        return None

    with open(filepath, "rb") as f:
        plaintext = f.read()

    document_key = os.urandom(32)
    nonce = os.urandom(12)
    document_id = os.urandom(16)

    filename = os.path.basename(filepath).encode()
    mime_type = b"application/octet-stream"

    doc = Document(
        document_id=document_id,
        owner_id=owner_id.encode(),
        filename=filename,
        mime_type=mime_type,
        size=len(plaintext),
        timestamp=int(time.time()),
        nonce=nonce,
        ciphertext=b"",
        tag=b"",
    )

    ciphertext, tag = aead_encrypt(document_key, nonce, doc.get_aad(), plaintext)
    doc.ciphertext = ciphertext
    doc.tag = tag

    transport.send_message(transport.SERVER_INBOX, doc.to_bytes())

    store_document_key_locally(owner_id, wrap_key, document_id, document_key, client_dir)

    print(f"Uploaded '{filepath}' as document {document_id.hex()}")
    print("Document key saved locally -- no need to re-enter it to download.")
    return document_id


def cmd_download(document_id_hex: str, owner_id: str, output_path: str, client_dir=None, timeout: float = 10.0):
    wrap_key = _load_wrap_key(owner_id, client_dir)
    if wrap_key is None:
        print("You must be logged in to download. Run 'login' first.")
        return None

    target_id = bytes.fromhex(document_id_hex)
    document_key = load_document_key_locally(owner_id, wrap_key, target_id, client_dir)
    if document_key is None:
        print("No locally-stored key for this document (not yours, or not uploaded/received on this machine).")
        return None

    req = GetRequest(owner_id.encode(), b"documents", document_id_hex.encode())
    transport.send_message(transport.SERVER_INBOX, req.to_bytes())

    result = transport.wait_for_message(owner_id, timeout=timeout)
    if result is None:
        print("No response from server (timeout)")
        return None

    filename, payload = result
    transport.consume_message(owner_id, filename)

    if payload == b"\x00NOT_FOUND":
        print(f"Document {document_id_hex} not found on server")
        return None

    try:
        doc = Document.from_bytes(payload)
    except ValueError:
        print("Malformed object")
        return None

    if doc.document_id != target_id:
        print("Verification failed: server returned the wrong document")
        return None

    try:
        plaintext = aead_decrypt(document_key, doc.nonce, doc.get_aad(), doc.ciphertext, doc.tag)
    except AuthenticationError:
        print("Verification failed: the document or its metadata was tampered with")
        return None

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Downloaded document {document_id_hex} -> '{output_path}'")
    print(f"Filename on record: {doc.filename.decode(errors='replace')}")
    return doc


def cmd_register(user_id: str, password: str, client_dir=None, timeout: float = 10.0):
    _client_dir(user_id, client_dir)
    account = accounts.register(user_id, password)

    result = _send_account_request(
        user_id,
        TYPE_REGISTER_REQUEST,
        {"records": account["records"]},
        timeout,
    )
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, body = result
    if type_byte == TYPE_ERROR:
        print(f"Registration failed: {body.get('error', 'unknown error')}")
        return None

    print(f"Registered user '{user_id}'")
    print(f"Public-key fingerprint: {account['fingerprint'].hex()}")
    return {
        "user_id": account["user_id"],
        "fingerprint": account["fingerprint"],
    }


def cmd_login(user_id: str, password: str, client_dir=None, timeout: float = 10.0):
    _client_dir(user_id, client_dir)
    user_id_bytes = accounts.encode_user_id(user_id)

    result = _send_account_request(
        user_id,
        TYPE_LOGIN_BEGIN_REQUEST,
        {"user_id": user_id_bytes},
        timeout,
    )
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, challenge = result
    if type_byte == TYPE_ERROR:
        print("Authentication failed")
        return None

    try:
        response, local_state = accounts.make_login_response_with_state(password, challenge)
    except ValueError:
        print("Authentication failed")
        return None

    result = _send_account_request(
        user_id,
        TYPE_LOGIN_FINISH_REQUEST,
        response,
        timeout,
    )
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, accepted = result
    if type_byte == TYPE_ERROR:
        print("Authentication failed")
        return None

    try:
        bundle = private_keys.unwrap_private_keys(
            accepted["user_id"], local_state["wrap_key"], accepted["wrapped_private_key"]
        )
        public_key = accounts._check_login_public_key(
            accepted["user_id"], accepted["public_key"], bundle
        )
        session_public = accepted["session"]
        session = {
            "session_id": session_public["session_id"],
            "user_id": accepted["user_id"],
            "expires_at": session_public["expires_at"],
            "session_key": accounts._derive_session_key(
                local_state["login_key"], session_public["session_id"]
            ),
        }
    except ValueError:
        print("Authentication failed")
        return None

    _save_local_session(user_id, session, bundle, local_state["wrap_key"], client_dir)
    fingerprint = accounts.public_key_fingerprint(public_key)

    print(f"Logged in as '{user_id}'")
    print(f"Public-key fingerprint: {fingerprint.hex()}")
    print(f"Session expires at (unix time): {session['expires_at']}")

    return {
        "user_id": accepted["user_id"],
        "session": session,
        "bundle": bundle,
        "wrap_key": local_state["wrap_key"],
        "public_key": public_key,
        "fingerprint": fingerprint,
    }


def cmd_logout(user_id: str, client_dir=None, timeout: float = 10.0):
    session = _load_local_session(user_id, client_dir)
    if session is None:
        print("No active session")
        return None

    try:
        request = accounts.make_session_request(session, accounts.LOGOUT_OPERATION)
    except ValueError:
        print("Authentication failed")
        return None

    result = _send_account_request(user_id, TYPE_SESSION_REQUEST, request, timeout)
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, body = result
    if type_byte == TYPE_ERROR:
        print("Authentication failed")
        return None

    _delete_local_session(user_id, client_dir)
    print(f"Logged out '{user_id}'")
    return body


def cmd_change_password(
    user_id: str,
    old_password: str,
    new_password: str,
    client_dir=None,
    timeout: float = 10.0,
):
    session = _load_local_session(user_id, client_dir)
    if session is None:
        print("No active session")
        return None

    try:
        context_request = accounts.make_session_request(
            session, accounts.PASSWORD_CHANGE_CONTEXT_OPERATION
        )
    except ValueError:
        print("Authentication failed")
        return None

    result = _send_account_request(user_id, TYPE_SESSION_REQUEST, context_request, timeout)
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, context = result
    if type_byte == TYPE_ERROR:
        print("Authentication failed")
        return None

    try:
        change_request, local_state = accounts.prepare_password_change(
            user_id,
            old_password,
            new_password,
            context,
            session,
        )
    except ValueError:
        print("Authentication failed")
        return None

    result = _send_account_request(user_id, TYPE_SESSION_REQUEST, change_request, timeout)
    if result is None:
        print("No response from server (timeout)")
        return None

    type_byte, body = result
    if type_byte == TYPE_ERROR:
        print("Authentication failed")
        return None

    _delete_local_session(user_id, client_dir)
    print(f"Password changed for '{user_id}'. Log in again with the new password.")
    return {
        "user_id": body["user_id"],
        "password_changed": body["password_changed"],
        "fingerprint": local_state["fingerprint"],
    }


def cmd_share(document_id_hex: str, sender_id: str, recipient_id: str, client_dir=None, timeout: float = 10.0):
    bundle = load_recovered_keys(sender_id, client_dir)
    if bundle is None:
        print("You must be logged in to share. Run 'login' first.")
        return None

    wrap_key = _load_wrap_key(sender_id, client_dir)
    document_id = bytes.fromhex(document_id_hex)
    document_key = load_document_key_locally(sender_id, wrap_key, document_id, client_dir)
    if document_key is None:
        print("No locally-stored key for this document -- it isn't yours, or wasn't uploaded from this machine.")
        return None

    recipient_pk = get_and_trust_public_key(sender_id, recipient_id, client_dir, timeout)
    if recipient_pk is None:
        return None

    sequence_number = int(time.time() * 1000)
    timestamp = int(time.time())

    recipient_rsa_public = {
        "n": int.from_bytes(recipient_pk.rsa_modulus, "big"),
        "e": int.from_bytes(recipient_pk.rsa_public_exponent, "big"),
    }

    try:
        share = sharing.create_share(
            document_id=document_id,
            sender_id=sender_id.encode(),
            recipient_id=recipient_id.encode(),
            document_key=document_key,
            sender_p256_public=bundle["p256_public"],
            recipient_p256_public=recipient_pk.p256_public_key,
            sender_rsa_private=bundle["rsa_private"],
            sender_rsa_public=bundle["rsa_public"],
            recipient_rsa_public=recipient_rsa_public,
            sequence_number=sequence_number,
            timestamp=timestamp,
        )
    except ValueError as e:
        print(f"Could not create share: {e}")
        return None

    transport.send_message(transport.SERVER_INBOX, share.to_bytes())
    print(f"Shared document {document_id_hex} with '{recipient_id}'")
    return share


def cmd_receive(user_id: str, client_dir=None, timeout: float = 10.0):
    bundle = load_recovered_keys(user_id, client_dir)
    if bundle is None:
        print("You must be logged in to receive. Run 'login' first.")
        return None

    wrap_key = _load_wrap_key(user_id, client_dir)

    req = GetRequest(user_id.encode(), b"shares", b"")
    transport.send_message(transport.SERVER_INBOX, req.to_bytes())

    result = transport.wait_for_message(user_id, timeout=timeout)
    if result is None:
        print("No response from server (timeout)")
        return None
    filename, payload = result
    transport.consume_message(user_id, filename)

    if payload == b"\x00NOT_FOUND":
        print("No pending shares")
        return []

    shares_bytes = []
    offset = 0
    while offset < len(payload):
        item, offset = unpack_str(payload, offset)
        shares_bytes.append(item)

    trusted_keys = _load_trusted_keys(user_id, client_dir)
    freshness_state = load_freshness_state(_freshness_path(user_id, client_dir))

    received = []
    for raw in shares_bytes:
        try:
            share = Share.from_bytes(raw)
        except ValueError:
            print("Skipped a malformed share")
            continue

        sender_id = share.sender_id.decode("utf-8")

        sender_pk = get_and_trust_public_key(user_id, sender_id, client_dir, timeout)
        if sender_pk is None:
            print(f"Skipped share from '{sender_id}' -- could not establish trust")
            continue
        trusted_keys = _load_trusted_keys(user_id, client_dir)
        sender_rsa_public = {
            "n": int.from_bytes(sender_pk.rsa_modulus, "big"),
            "e": int.from_bytes(sender_pk.rsa_public_exponent, "big"),
        }

        try:
            document_key = sharing.verify_and_unwrap_share(
                share,
                bundle["p256_private"],
                sender_rsa_public,
                freshness_state,
                trusted_keys,
            )
        except ValueError as e:
            print(f"Rejected share for document {share.document_id.hex()} from '{sender_id}': {e}")
            continue

        store_document_key_locally(user_id, wrap_key, share.document_id, document_key, client_dir)
        print(f"Accepted share: document {share.document_id.hex()} from '{sender_id}'")
        received.append(share.document_id.hex())

    save_freshness_state(_freshness_path(user_id, client_dir), freshness_state)
    return received


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    try:
        if command == "upload" and len(args) == 2:
            cmd_upload(args[0], args[1])
        elif command == "download" and len(args) == 3:
            cmd_download(args[0], args[1], args[2])
        elif command == "register" and len(args) == 2:
            cmd_register(args[0], args[1])
        elif command == "login" and len(args) == 2:
            cmd_login(args[0], args[1])
        elif command == "logout" and len(args) == 1:
            cmd_logout(args[0])
        elif command == "change-password" and len(args) == 3:
            cmd_change_password(args[0], args[1], args[2])
        elif command == "share" and len(args) == 3:
            cmd_share(args[0], args[1], args[2])
        elif command == "receive" and len(args) == 1:
            cmd_receive(args[0])
        else:
            print(__doc__)
    except NotImplementedError as e:
        print(f"Not available yet: {e}")


if __name__ == "__main__":
    main()
