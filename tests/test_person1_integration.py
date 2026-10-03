import subprocess
import sys
import time
from pathlib import Path

import accounts
import client
import transport
from account_store import AccountStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER_SCRIPT = PROJECT_ROOT / "server.py"


def _start_server(workdir):
    process = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.35)
    if process.poll() is not None:
        stdout, stderr = process.communicate(timeout=2)
        raise AssertionError(f"Server failed to start:\n{stdout}\n{stderr}")
    return process


def _stop_server(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def test_account_flow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    client_a_dir = tmp_path / "client_a"
    client_b_dir = tmp_path / "client_b"
    account_db = tmp_path / "server_private" / "accounts.db"

    alice = "alice"
    bob = "bob"
    alice_old = "Alice-old-password-123!"
    bob_old = "Bob-old-password-123!"
    alice_new = "Alice-new-password-456!"
    bob_new = "Bob-new-password-456!"

    process = _start_server(tmp_path)
    try:
        alice_registered = client.cmd_register(
            alice, alice_old, client_dir=client_a_dir, timeout=20
        )
        bob_registered = client.cmd_register(
            bob, bob_old, client_dir=client_b_dir, timeout=20
        )

        assert alice_registered is not None
        assert bob_registered is not None
        assert alice_registered["user_id"] == b"alice"
        assert bob_registered["user_id"] == b"bob"
        assert alice_registered["fingerprint"] != bob_registered["fingerprint"]

        alice_first = client.cmd_login(
            alice, alice_old, client_dir=client_a_dir, timeout=20
        )
        bob_first = client.cmd_login(
            bob, bob_old, client_dir=client_b_dir, timeout=20
        )

        assert alice_first is not None
        assert bob_first is not None
        assert alice_first["user_id"] == b"alice"
        assert bob_first["user_id"] == b"bob"
        assert alice_first["session"]["session_id"] != bob_first["session"]["session_id"]
        assert alice_first["fingerprint"] == alice_registered["fingerprint"]
        assert bob_first["fingerprint"] == bob_registered["fingerprint"]
        assert (client_a_dir / "session.json").exists()
        assert (client_b_dir / "session.json").exists()

        alice_logout = client.cmd_logout(alice, client_dir=client_a_dir, timeout=20)
        bob_logout = client.cmd_logout(bob, client_dir=client_b_dir, timeout=20)

        assert alice_logout == {"logged_out": True, "user_id": b"alice"}
        assert bob_logout == {"logged_out": True, "user_id": b"bob"}
        assert not (client_a_dir / "session.json").exists()
        assert not (client_b_dir / "session.json").exists()

        alice_second = client.cmd_login(
            alice, alice_old, client_dir=client_a_dir, timeout=20
        )
        bob_second = client.cmd_login(
            bob, bob_old, client_dir=client_b_dir, timeout=20
        )

        assert alice_second is not None
        assert bob_second is not None

        alice_changed = client.cmd_change_password(
            alice,
            alice_old,
            alice_new,
            client_dir=client_a_dir,
            timeout=20,
        )
        bob_changed = client.cmd_change_password(
            bob,
            bob_old,
            bob_new,
            client_dir=client_b_dir,
            timeout=20,
        )

        assert alice_changed is not None and alice_changed["password_changed"] is True
        assert bob_changed is not None and bob_changed["password_changed"] is True
        assert alice_changed["fingerprint"] == alice_registered["fingerprint"]
        assert bob_changed["fingerprint"] == bob_registered["fingerprint"]
        assert not (client_a_dir / "session.json").exists()
        assert not (client_b_dir / "session.json").exists()

        store = AccountStore(account_db)
        assert accounts.account_exists(store, alice)
        assert accounts.account_exists(store, bob)
        alice_records_before = store.get_account(b"alice")
        bob_records_before = store.get_account(b"bob")
        assert alice_records_before != bob_records_before
    finally:
        _stop_server(process)

    # Start a fresh server process over the same private database and shared root.
    process = _start_server(tmp_path)
    try:
        store = AccountStore(account_db)
        assert accounts.account_exists(store, alice)
        assert accounts.account_exists(store, bob)
        assert store.get_account(b"alice") == alice_records_before
        assert store.get_account(b"bob") == bob_records_before

        alice_after_restart = client.cmd_login(
            alice, alice_new, client_dir=client_a_dir, timeout=20
        )
        bob_after_restart = client.cmd_login(
            bob, bob_new, client_dir=client_b_dir, timeout=20
        )

        assert alice_after_restart is not None
        assert bob_after_restart is not None
        assert alice_after_restart["user_id"] == b"alice"
        assert bob_after_restart["user_id"] == b"bob"
        assert alice_after_restart["fingerprint"] == alice_registered["fingerprint"]
        assert bob_after_restart["fingerprint"] == bob_registered["fingerprint"]
        assert alice_after_restart["fingerprint"] != bob_after_restart["fingerprint"]

        shared_root = tmp_path / transport.SHARED_ROOT
        assert (shared_root / transport.SERVER_INBOX).is_dir()
        assert (shared_root / alice).is_dir()
        assert (shared_root / bob).is_dir()
        assert client_a_dir.is_dir()
        assert client_b_dir.is_dir()
        assert client_a_dir.resolve() != client_b_dir.resolve()
    finally:
        _stop_server(process)


def _wait_for_path(path, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {path}")


def _request_server_object(requester_id, store_name, key=b"", timeout=10.0):
    import server

    request = server.GetRequest(
        requester_id.encode("utf-8"),
        store_name.encode("utf-8"),
        key,
    )
    transport.send_message(transport.SERVER_INBOX, request.to_bytes())
    result = transport.wait_for_message(requester_id, timeout=timeout)
    assert result is not None
    filename, payload = result
    transport.consume_message(requester_id, filename)
    assert payload != server.NOT_FOUND_MARKER
    return payload


def _decode_share_list(payload):
    from crypto.formats import Share, unpack_str

    shares = []
    offset = 0
    while offset < len(payload):
        item, offset = unpack_str(payload, offset)
        shares.append(Share.from_bytes(item))
    return shares


def _server_bytes(root):
    data = bytearray()
    for folder in (root / "shared_network", root / "server_storage", root / "server_private"):
        if not folder.exists():
            continue
        for path in folder.rglob("*"):
            if path.is_file():
                data.extend(path.read_bytes())
    return bytes(data)


def _private_material(bundle):
    rsa = bundle["rsa_private"]
    return (
        bundle["p256_private"],
        rsa["d"].to_bytes(384, "big"),
        rsa["p"].to_bytes(192, "big"),
        rsa["q"].to_bytes(192, "big"),
    )


def test_sharing_interfaces(tmp_path, monkeypatch):
    from crypto.aead import aead_decrypt, aead_encrypt
    from crypto.formats import Document, Share
    from person1_interfaces import hkdf, pss_sign, pss_verify
    from sharing import create_share, verify_and_unwrap_share, verify_share
    from trust import trust_first_key

    monkeypatch.chdir(tmp_path)

    layla_dir = tmp_path / "client_layla"
    omar_dir = tmp_path / "client_omar"
    layla_old = "Layla-old-password-123!"
    layla_new = "Layla-new-password-456!"
    omar_password = "Omar-password-123!"

    process = _start_server(tmp_path)
    try:
        assert client.cmd_register("layla", layla_old, client_dir=layla_dir, timeout=20)
        assert client.cmd_register("omar", omar_password, client_dir=omar_dir, timeout=20)

        layla_login = client.cmd_login("layla", layla_old, client_dir=layla_dir, timeout=20)
        omar_login = client.cmd_login("omar", omar_password, client_dir=omar_dir, timeout=20)
        assert layla_login is not None
        assert omar_login is not None

        # Person 1 exposes recovered identity keys through the client boundary.
        layla_keys_before = client.load_recovered_keys("layla", layla_dir)
        omar_keys = client.load_recovered_keys("omar", omar_dir)
        assert layla_keys_before == layla_login["bundle"]
        assert omar_keys == omar_login["bundle"]

        # Person 1's explicit signing / verification / HKDF interfaces match
        # the call signatures consumed by Person 3's sharing implementation.
        interface_message = b"person1-sharing-interface-check"
        signature = pss_sign(layla_keys_before["rsa_private"], interface_message)
        assert pss_verify(layla_keys_before["rsa_public"], interface_message, signature)
        assert hkdf(b"shared-secret", b"salt", b"info", 32) == hkdf(
            b"shared-secret", b"salt", b"info", 32
        )

        document_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        document_key = bytes(range(32))
        plaintext = b"SecureVault Step 14 sharing test document"
        nonce = bytes.fromhex("000102030405060708090a0b")

        document = Document(
            document_id=document_id,
            owner_id=b"layla",
            filename=b"step14.txt",
            mime_type=b"text/plain",
            size=len(plaintext),
            timestamp=1000,
            nonce=nonce,
            ciphertext=b"",
            tag=b"",
        )
        ciphertext, tag = aead_encrypt(
            document_key, document.nonce, document.get_aad(), plaintext
        )
        document.ciphertext = ciphertext
        document.tag = tag
        transport.send_message(transport.SERVER_INBOX, document.to_bytes())
        _wait_for_path(
            tmp_path / "server_storage" / "documents" / f"{document_id.hex()}.obj"
        )

        share1 = create_share(
            document_id,
            b"layla",
            b"omar",
            document_key,
            layla_keys_before["p256_public"],
            omar_keys["p256_public"],
            layla_keys_before["rsa_private"],
            layla_keys_before["rsa_public"],
            omar_keys["rsa_public"],
            1,
            1000,
        )
        transport.send_message(transport.SERVER_INBOX, share1.to_bytes())
        share_dir = tmp_path / "server_storage" / "shares" / "omar"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if share_dir.is_dir() and list(share_dir.glob("*.obj")):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Timed out waiting for stored share")

        # Omar retrieves Person 3's Share object through the real server/transport.
        share_payload = _request_server_object("omar", "shares", timeout=20)
        retrieved_shares = _decode_share_list(share_payload)
        retrieved1 = next(item for item in retrieved_shares if item.sequence_number == 1)
        assert verify_share(retrieved1, layla_keys_before["rsa_public"])

        trusted_keys = {}
        assert trust_first_key(
            trusted_keys,
            "layla",
            layla_keys_before["p256_public"],
            layla_keys_before["rsa_public"]["n"],
            layla_keys_before["rsa_public"]["e"],
        )
        freshness_state = {}
        recovered_document_key = verify_and_unwrap_share(
            retrieved1,
            omar_keys["p256_private"],
            layla_keys_before["rsa_public"],
            freshness_state,
            trusted_keys,
        )
        assert recovered_document_key == document_key

        stored_document_bytes = _request_server_object(
            "omar", "documents", document_id.hex().encode("utf-8"), timeout=20
        )
        stored_document = Document.from_bytes(stored_document_bytes)
        assert aead_decrypt(
            recovered_document_key,
            stored_document.nonce,
            stored_document.get_aad(),
            stored_document.ciphertext,
            stored_document.tag,
        ) == plaintext

        # Changing any signed field must invalidate Person 3's RSA-PSS verification.
        tampered = Share.from_bytes(retrieved1.to_bytes())
        tampered.timestamp += 1
        assert tampered.signed_bytes() != retrieved1.signed_bytes()
        assert verify_share(tampered, layla_keys_before["rsa_public"]) is False

        # Password change re-wraps the same identity keys; it does not replace them.
        changed = client.cmd_change_password(
            "layla",
            layla_old,
            layla_new,
            client_dir=layla_dir,
            timeout=20,
        )
        assert changed is not None and changed["password_changed"] is True
        assert client.load_recovered_keys("layla", layla_dir) is None

        layla_after_change = client.cmd_login(
            "layla", layla_new, client_dir=layla_dir, timeout=20
        )
        assert layla_after_change is not None
        layla_keys_after = client.load_recovered_keys("layla", layla_dir)
        assert layla_keys_after == layla_keys_before

        # Existing document access still works after Layla changes her password.
        assert aead_decrypt(
            recovered_document_key,
            stored_document.nonce,
            stored_document.get_aad(),
            stored_document.ciphertext,
            stored_document.tag,
        ) == plaintext

        # The same recovered identity keys can create a later valid share.
        share2 = create_share(
            document_id,
            b"layla",
            b"omar",
            document_key,
            layla_keys_after["p256_public"],
            omar_keys["p256_public"],
            layla_keys_after["rsa_private"],
            layla_keys_after["rsa_public"],
            omar_keys["rsa_public"],
            2,
            1001,
        )
        transport.send_message(transport.SERVER_INBOX, share2.to_bytes())
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if share_dir.is_dir() and len(list(share_dir.glob("*.obj"))) >= 2:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Timed out waiting for second stored share")

        share_payload = _request_server_object("omar", "shares", timeout=20)
        retrieved_shares = _decode_share_list(share_payload)
        retrieved2 = next(item for item in retrieved_shares if item.sequence_number == 2)
        recovered_after_change = verify_and_unwrap_share(
            retrieved2,
            omar_keys["p256_private"],
            layla_keys_after["rsa_public"],
            freshness_state,
            trusted_keys,
        )
        assert recovered_after_change == document_key

        # Shared/server-side storage must never contain plaintext private keys.
        server_bytes = _server_bytes(tmp_path)
        for secret in _private_material(layla_keys_after) + _private_material(omar_keys):
            assert secret not in server_bytes
    finally:
        _stop_server(process)
