import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import transport
import server
from server import GetRequest
from crypto.formats import Document, PublicKey, Share, unpack_str, pack_str
from crypto.aead import aead_encrypt, aead_decrypt, AuthenticationError
from crypto.sha256 import sha256
import client


def _reset():
    import shutil
    for d in ("shared_network", "server_storage", "server_private"):
        if os.path.isdir(d):
            shutil.rmtree(d)
        if os.path.isdir(DEFAULT_TMP):
            shutil.rmtree(DEFAULT_TMP)

    from account_store import AccountStore
    server.account_store = AccountStore(server.ACCOUNT_DB_PATH)
import threading

def _server_thread(stop_event, delay=0.01):
    while not stop_event.is_set():
        server.run_once()
        time.sleep(delay)

import tempfile
DEFAULT_TMP = os.path.join(tempfile.gettempdir(), "e2e_test")

def test_client_upload_download_roundtrip(tmp_dir=DEFAULT_TMP):
    _reset()
    os.makedirs(tmp_dir, exist_ok=True)

    src_path = os.path.join(tmp_dir, "thesis-draft.pdf")
    out_path = os.path.join(tmp_dir, "downloaded.pdf")
    client_dir = os.path.join(DEFAULT_TMP, "layla_client2")

    original_content = b"This is Layla's secret thesis content, exactly as written."

    with open(src_path, "wb") as f:
        f.write(original_content)

    stop_event = threading.Event()
    server_thread = threading.Thread(
        target=_server_thread,
        args=(stop_event,),
        daemon=True,
    )
    server_thread.start()

    try:
        login_result = None

        result = client.cmd_register(
            "layla",
            "test-password-123!",
            client_dir=client_dir,
            timeout=30.0,
        )
        assert result is not None

        login_result = client.cmd_login(
            "layla",
            "test-password-123!",
            client_dir=client_dir,
            timeout=30.0,
        )
        assert login_result is not None

        document_id = client.cmd_upload(
            src_path,
            "layla",
            client_dir=client_dir,
        )
        assert document_id is not None

        doc = client.cmd_download(
            document_id.hex(),
            "layla",
            out_path,
            client_dir=client_dir,
            timeout=30.0,
        )
        assert doc is not None

        with open(out_path, "rb") as f:
            assert f.read() == original_content

    finally:
        stop_event.set()
        server_thread.join(timeout=2.0)

def test_full_server_mediated_flow():
    _reset()

    client_dir = os.path.join(DEFAULT_TMP, "layla_client2")

    import shutil
    if os.path.isdir(client_dir):
        shutil.rmtree(client_dir)

    stop_event = threading.Event()
    t = threading.Thread(
        target=_server_thread,
        args=(stop_event,),
        daemon=True,
    )
    t.start()

    try:
        result = client.cmd_register(
            "layla2",
            "test-password-456!",
            client_dir=client_dir,
            timeout=60.0,
        )

        assert result is not None

        stored = server.account_store.get_account(b"layla2")
        assert stored is not None, "Account was not persisted atomically by the server"
        assert set(stored.keys()) == {
            "credential",
            "public_key",
            "wrapped_private_key",
        }

    finally:
        stop_event.set()
        t.join(timeout=2.0)

def test_tampered_ciphertext_rejected_end_to_end():
    _reset()

    document_key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"secret content"
    doc = Document(os.urandom(16), b"layla", b"file.pdf", b"application/pdf",
                    len(plaintext), int(time.time()), nonce, b"", b"")
    ciphertext, tag = aead_encrypt(document_key, nonce, doc.get_aad(), plaintext)
    doc.ciphertext, doc.tag = ciphertext, tag
    transport.send_message(transport.SERVER_INBOX, doc.to_bytes())
    server.run_once()

    req = GetRequest(requester_id=b"omar", store=b"documents", key=doc.document_id.hex().encode())
    transport.send_message(transport.SERVER_INBOX, req.to_bytes())
    server.run_once()
    _, response = transport.poll_messages("omar")[0]

    tampered = bytearray(response)
    tampered[-1] ^= 0x01
    tampered_doc = Document.from_bytes(bytes(tampered))

    try:
        aead_decrypt(document_key, tampered_doc.nonce, tampered_doc.get_aad(),
                     tampered_doc.ciphertext, tampered_doc.tag)
        assert False, "tampered document should have been rejected"
    except AuthenticationError:
        print("tampered document rejected end to end: OK")


def test_document_not_found_reports_cleanly():
    _reset()
    req = GetRequest(requester_id=b"omar", store=b"documents", key=os.urandom(16).hex().encode())
    transport.send_message(transport.SERVER_INBOX, req.to_bytes())
    server.run_once()
    _, response = transport.poll_messages("omar")[0]
    assert response == server.NOT_FOUND_MARKER
    print("missing document reports NOT_FOUND cleanly: OK")


def test_server_survives_garbage_in_shared_directory():
    _reset()
    transport.send_message(transport.SERVER_INBOX, b"complete garbage, not a real object")
    transport.send_message(transport.SERVER_INBOX, b"")
    transport.send_message(transport.SERVER_INBOX, bytes([1, 4]) + b"looks like a header but isn't valid")
    processed = server.run_once()
    assert processed == 3
    print("server survives malformed/garbage input without crashing: OK")


if __name__ == "__main__":
    test_client_upload_download_roundtrip()
    test_full_server_mediated_flow()
    test_tampered_ciphertext_rejected_end_to_end()
    test_document_not_found_reports_cleanly()
    test_server_survives_garbage_in_shared_directory()
    _reset()
    print("\nALL END-TO-END TESTS PASSED")
