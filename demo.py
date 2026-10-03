"""Interactive step-by-step demo runner for SecureVault.

Run it from the project root:

    python demo.py

Each action is a numbered menu item, so the demo can be driven one step at a
time during the presentation instead of running everything at once.

A suggested order for the live demo:

    3  reset
    1  start the server
    4  register Layla        5  register Omar
    16 inspect the account database
    6  log in Layla          7  log in Omar
    8  create a sample file
    9  upload
    17 inspect server storage
    18 inspect the encrypted document bytes
    10 share                 11 receive        12 download
    13 replay the share      14 tamper with the document
    15 tamper with the share 19 substitute a public key
"""

import os
import shutil
import sqlite3
import threading
import time

import client
import server
import transport
from account_store import AccountStore
from crypto.formats import Credential, Document, PublicKey, Share


LAYLA = "layla"
OMAR = "omar"
LAYLA_PASSWORD = "Layla-demo-password-123!"
OMAR_PASSWORD = "Omar-demo-password-123!"
NEW_LAYLA_PASSWORD = "Layla-new-password-456!"

DEMO_ROOT = "demo_state"
SAMPLE_NAME = "thesis-draft.txt"
SAMPLE_TEXT = b"CONFIDENTIAL: Layla's thesis draft. If you can read this on the server, the design failed."

RUNTIME_DIRS = ("shared_network", "server_storage", "server_private", DEMO_ROOT)

state = {
    "server_thread": None,
    "stop_event": None,
    "document_id": None,
    "share_bytes": None,
}


# ----------------------------------------------------------------- helpers

def client_dir(user_id):
    path = os.path.join(DEMO_ROOT, user_id)
    os.makedirs(path, exist_ok=True)
    return path


def sample_path():
    return os.path.join(DEMO_ROOT, SAMPLE_NAME)


def banner(text):
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


def note(text):
    print("    " + text)


def require_document():
    if state["document_id"] is None:
        print("No document yet. Run step 9 (upload) first.")
        return None
    return state["document_id"]


def server_is_running():
    thread = state["server_thread"]
    return thread is not None and thread.is_alive()


def _server_loop(stop_event, delay=0.05):
    while not stop_event.is_set():
        try:
            server.run_once()
        except Exception as error:
            print("server loop error:", repr(error))
        time.sleep(delay)


def hex_preview(data, width=32):
    if data is None:
        return "(none)"
    shown = data[:width].hex()
    if len(data) > width:
        shown += " ..."
    return shown


# ----------------------------------------------------------------- 1, 2, 3

def step_start_server():
    banner("1  START THE SERVER")
    if server_is_running():
        note("The server is already running.")
        return
    stop_event = threading.Event()
    thread = threading.Thread(target=_server_loop, args=(stop_event,), daemon=True)
    thread.start()
    state["stop_event"] = stop_event
    state["server_thread"] = thread
    time.sleep(0.3)
    note(f"Watching {transport.SHARED_ROOT}/{transport.SERVER_INBOX} for message files.")
    note("The server holds no user key: it only stores and relays objects.")


def step_stop_server():
    banner("2  STOP THE SERVER")
    if not server_is_running():
        note("The server is not running.")
        return
    state["stop_event"].set()
    state["server_thread"].join(timeout=3.0)
    state["server_thread"] = None
    state["stop_event"] = None
    note("Stopped. Account data stays on disk, so step 1 can resume from it.")


def step_reset():
    banner("3  RESET EVERYTHING")
    if server_is_running():
        state["stop_event"].set()
        state["server_thread"].join(timeout=3.0)
        state["server_thread"] = None
        state["stop_event"] = None
        note("Stopped the running server first.")

    for directory in RUNTIME_DIRS:
        if os.path.isdir(directory):
            shutil.rmtree(directory, ignore_errors=True)
            note(f"removed {directory}/")

    server.account_store = AccountStore(server.ACCOUNT_DB_PATH)
    state["document_id"] = None
    state["share_bytes"] = None
    note("Fresh state. Start again from step 1.")


# ----------------------------------------------------------------- 4, 5

def register(user_id, password):
    banner(f"REGISTER '{user_id}'")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    note("The client generates RSA-3072 and P-256 keys locally. This takes a few seconds.")
    result = client.cmd_register(user_id, password, client_dir=client_dir(user_id), timeout=90.0)
    if result is None:
        note("Registration failed.")
        return
    note("Only three records were sent: Credential, PublicKey, WrappedPrivateKey.")
    note("The password, the wrap key and the private keys never left this machine.")


def step_register_layla():
    register(LAYLA, LAYLA_PASSWORD)


def step_register_omar():
    register(OMAR, OMAR_PASSWORD)


# ----------------------------------------------------------------- 6, 7

def login(user_id, password):
    banner(f"LOG IN '{user_id}'")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    result = client.cmd_login(user_id, password, client_dir=client_dir(user_id), timeout=90.0)
    if result is None:
        note("Login failed.")
        return
    note("The server sent a one-time challenge; the client answered with an HMAC")
    note("over the transcript, and only then received the wrapped private key.")
    note("Compare the fingerprint above out of band before a first share.")


def step_login_layla():
    login(LAYLA, LAYLA_PASSWORD)


def step_login_omar():
    login(OMAR, OMAR_PASSWORD)


# ----------------------------------------------------------------- 8, 9

def step_create_sample():
    banner("8  CREATE A SAMPLE FILE")
    os.makedirs(DEMO_ROOT, exist_ok=True)
    with open(sample_path(), "wb") as handle:
        handle.write(SAMPLE_TEXT)
    note(f"wrote {sample_path()} ({len(SAMPLE_TEXT)} bytes)")
    print()
    print(SAMPLE_TEXT.decode())


def step_upload():
    banner("9  UPLOAD THE DOCUMENT (Layla)")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    if not os.path.exists(sample_path()):
        note("No sample file. Run step 8 first.")
        return

    document_id = client.cmd_upload(sample_path(), LAYLA, client_dir=client_dir(LAYLA))
    if document_id is None:
        note("Upload failed.")
        return

    state["document_id"] = document_id.hex()
    time.sleep(0.4)
    note("A fresh 32-byte key and 12-byte nonce were generated for this document alone.")
    note("Filename, MIME type, size, timestamp and owner are readable but authenticated.")
    note(f"document id: {state['document_id']}")


# ----------------------------------------------------------------- 10, 11, 12

def step_share():
    banner("10  SHARE THE DOCUMENT (Layla to Omar)")
    document_id = require_document()
    if document_id is None or not server_is_running():
        if document_id is not None:
            note("Start the server first (step 1).")
        return

    share = client.cmd_share(document_id, LAYLA, OMAR,
                             client_dir=client_dir(LAYLA), timeout=60.0)
    if share is None:
        note("Share failed.")
        return

    state["share_bytes"] = share.to_bytes()
    time.sleep(0.4)
    note("An ephemeral P-256 pair was used, so Layla's long-term key never")
    note("touched the key agreement. The share is signed with RSA-PSS.")
    note(f"sequence number {share.sequence_number}, signature {len(share.signature)} bytes")


def step_receive():
    banner("11  RECEIVE THE SHARE (Omar)")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    received = client.cmd_receive(OMAR, client_dir=client_dir(OMAR), timeout=60.0)
    if received:
        note("Checked in order: pinned sender, fingerprint, signature, freshness.")
        note("Only after all four did the client unwrap the document key.")
    else:
        note("Nothing was accepted. Any rejection reason is printed above.")


def step_download():
    banner("12  DOWNLOAD AND DECRYPT (Omar)")
    document_id = require_document()
    if document_id is None or not server_is_running():
        if document_id is not None:
            note("Start the server first (step 1).")
        return

    out_path = os.path.join(DEMO_ROOT, "recovered-" + SAMPLE_NAME)
    doc = client.cmd_download(document_id, OMAR, out_path,
                              client_dir=client_dir(OMAR), timeout=60.0)
    if doc is None:
        note("Download failed or was refused.")
        return

    with open(out_path, "rb") as handle:
        recovered = handle.read()

    print()
    print(recovered.decode(errors="replace"))
    print()
    note(f"identical to the original: {recovered == SAMPLE_TEXT}")
    note("The AEAD tag was verified before a single plaintext byte was written.")


# ----------------------------------------------------------------- 13, 14, 15, 19

def step_replay_share():
    banner("13  ATTACK: REPLAY THE SHARE")
    if state["share_bytes"] is None:
        note("No captured share. Run step 10 first.")
        return
    if not server_is_running():
        note("Start the server first (step 1).")
        return

    note("Re-sending the exact bytes of a share Omar already accepted.")
    transport.send_message(transport.SERVER_INBOX, state["share_bytes"])
    time.sleep(0.6)
    client.cmd_receive(OMAR, client_dir=client_dir(OMAR), timeout=60.0)
    print()
    note("Expected: 'Stale object'. The sequence number is signed, so it cannot")
    note("be raised without breaking Layla's signature.")


def step_tamper_document():
    banner("14  ATTACK: TAMPER WITH THE STORED DOCUMENT")
    document_id = require_document()
    if document_id is None:
        return

    path = os.path.join(server.STORAGE_ROOT, "documents", document_id + ".obj")
    if not os.path.exists(path):
        note(f"No stored object at {path}")
        return

    with open(path, "rb") as handle:
        stored = bytearray(handle.read())

    doc = Document.from_bytes(bytes(stored))
    position = stored.index(doc.ciphertext)
    stored[position] ^= 0x01
    with open(path, "wb") as handle:
        handle.write(bytes(stored))
    note(f"flipped one bit inside the ciphertext at offset {position}")

    out_path = os.path.join(DEMO_ROOT, "tampered-" + SAMPLE_NAME)
    result = client.cmd_download(document_id, OMAR, out_path,
                                 client_dir=client_dir(OMAR), timeout=60.0)
    print()
    note("Expected: the client refuses and writes nothing.")
    note(f"a file was written: {os.path.exists(out_path)}   download returned: {result}")


def step_tamper_share():
    banner("15  ATTACK: TAMPER WITH THE SHARE")
    if state["share_bytes"] is None:
        note("No captured share. Run step 10 first.")
        return
    if not server_is_running():
        note("Start the server first (step 1).")
        return

    share = Share.from_bytes(state["share_bytes"])
    share.sequence_number += 1
    note("Raised the sequence number to make the replay look fresh,")
    note("without touching the signature.")
    transport.send_message(transport.SERVER_INBOX, share.to_bytes())
    time.sleep(0.6)
    client.cmd_receive(OMAR, client_dir=client_dir(OMAR), timeout=60.0)
    print()
    note("Expected: 'Verification failed'. The sequence number is inside the")
    note("signed bytes, so editing it invalidates the RSA-PSS signature.")


def step_substitute_key():
    banner("19  ATTACK: SUBSTITUTE LAYLA'S PUBLIC KEY")
    try:
        trusted = client._load_trusted_keys(OMAR, client_dir(OMAR))
    except Exception as error:
        note(f"Could not read Omar's trust store: {error!r}")
        return

    if LAYLA not in trusted:
        note("Omar has not pinned Layla's key yet. Run step 11 first.")
        return

    fingerprint = bytearray(trusted[LAYLA]["fingerprint"])
    fingerprint[0] ^= 0x01
    trusted[LAYLA]["fingerprint"] = bytes(fingerprint)
    client._save_trusted_keys(OMAR, trusted, client_dir(OMAR))
    note("Changed the fingerprint Omar has pinned for Layla, which is what a")
    note("server substituting her public key would effectively cause.")

    if state["share_bytes"] is not None and server_is_running():
        transport.send_message(transport.SERVER_INBOX, state["share_bytes"])
        time.sleep(0.6)
    client.cmd_receive(OMAR, client_dir=client_dir(OMAR), timeout=60.0)
    print()
    note("Expected: the client refuses to proceed because the key changed.")
    note("Run step 3 afterwards; Omar's trust store is now deliberately wrong.")


# ----------------------------------------------------------------- 16, 17, 18

def step_show_database():
    banner("16  INSPECT THE SERVER'S ACCOUNT DATABASE")
    path = server.ACCOUNT_DB_PATH
    if not os.path.exists(path):
        note(f"No database yet at {path}")
        return

    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT user_id, kind, length(value) FROM records ORDER BY user_id, kind"
        ).fetchall()
    finally:
        connection.close()

    if not rows:
        note("The database exists but holds no accounts.")
        return

    print(f"{'user':<12}{'record':<22}{'bytes':>8}")
    print("-" * 42)
    for user_id, kind, size in rows:
        name = user_id.decode() if isinstance(user_id, bytes) else str(user_id)
        print(f"{name:<12}{kind:<22}{size:>8}")

    record = server.account_store.get("credential", LAYLA.encode())
    if record is None:
        return

    credential = Credential.from_bytes(record)
    print()
    note("Layla's credential record, field by field:")
    note(f"  salt            {credential.salt.hex()}")
    note(f"  argon2 params   {credential.argon2_params.hex()}")
    note(f"  stored verifier {credential.auth_value.hex()}")
    print()
    note("There is no password here and nothing that yields one cheaply:")
    note("the verifier is a hash of a value that costs one Argon2id run per guess.")


def step_show_storage():
    banner("17  INSPECT SERVER STORAGE")
    root = server.STORAGE_ROOT
    if not os.path.isdir(root):
        note(f"No storage directory yet at {root}")
        return

    found = False
    for current, _dirs, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(current, name)
            print(f"    {full}   {os.path.getsize(full)} bytes")
            found = True
    if not found:
        note("The storage directory is empty.")
        return

    print()
    note("The server holds encrypted Document objects and signed Share objects.")
    note("It has no document key and no user private key, so it cannot read any of them.")


def step_show_encrypted_bytes():
    banner("18  INSPECT THE ENCRYPTED DOCUMENT BYTES")
    document_id = require_document()
    if document_id is None:
        return

    path = os.path.join(server.STORAGE_ROOT, "documents", document_id + ".obj")
    if not os.path.exists(path):
        note(f"No stored object at {path}")
        return

    with open(path, "rb") as handle:
        stored = handle.read()

    doc = Document.from_bytes(stored)
    note("What the server can read:")
    note(f"  document id  {doc.document_id.hex()}")
    note(f"  owner        {doc.owner_id.decode()}")
    note(f"  filename     {doc.filename.decode()}")
    note(f"  mime type    {doc.mime_type.decode()}")
    note(f"  size         {doc.size} bytes")
    note(f"  timestamp    {doc.timestamp}")
    print()
    note("What it cannot read:")
    note(f"  nonce        {doc.nonce.hex()}")
    note(f"  ciphertext   {hex_preview(doc.ciphertext, 48)}")
    note(f"  tag          {doc.tag.hex()}")
    print()

    leak = SAMPLE_TEXT[:24]
    note(f"plaintext fragment present in the stored object: {leak in stored}")
    note("Every readable field above is inside the AEAD associated data, so")
    note("changing any one of them makes the tag check fail (step 14).")


# ----------------------------------------------------------------- 20, 21, 22

def step_change_password():
    banner("20  CHANGE LAYLA'S PASSWORD")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    result = client.cmd_change_password(LAYLA, LAYLA_PASSWORD, NEW_LAYLA_PASSWORD,
                                        client_dir=client_dir(LAYLA), timeout=90.0)
    if result is None:
        note("Password change failed.")
        return
    note("Same identity keys, re-wrapped under a new wrap key.")
    note(f"fingerprint after the change: {result['fingerprint'].hex()}")
    note("Every session for Layla was invalidated in the same transaction.")
    note(f"Log in again with: {NEW_LAYLA_PASSWORD}")


def step_logout():
    banner("21  LOG BOTH USERS OUT")
    if not server_is_running():
        note("Start the server first (step 1).")
        return
    for user_id in (LAYLA, OMAR):
        client.cmd_logout(user_id, client_dir=client_dir(user_id), timeout=60.0)
    note("Local session files were deleted and the server marked the sessions invalid.")


def step_status():
    banner("22  CURRENT STATE")
    note(f"server running    {server_is_running()}")
    note(f"document id       {state['document_id'] or '(none)'}")
    note(f"captured share    {'yes' if state['share_bytes'] else 'no'}")
    for user_id in (LAYLA, OMAR):
        path = os.path.join(DEMO_ROOT, user_id)
        session = os.path.join(path, "session.json")
        note(f"{user_id:<6} dir {path}   logged in: {os.path.exists(session)}")


# ----------------------------------------------------------------- menu

MENU = [
    ("1", "Start the server", step_start_server),
    ("2", "Stop the server", step_stop_server),
    ("3", "Reset everything", step_reset),
    ("4", "Register Layla", step_register_layla),
    ("5", "Register Omar", step_register_omar),
    ("6", "Log in Layla", step_login_layla),
    ("7", "Log in Omar", step_login_omar),
    ("8", "Create the sample file", step_create_sample),
    ("9", "Upload the document (Layla)", step_upload),
    ("10", "Share the document with Omar", step_share),
    ("11", "Receive the share (Omar)", step_receive),
    ("12", "Download and decrypt (Omar)", step_download),
    ("13", "Attack: replay the share", step_replay_share),
    ("14", "Attack: tamper with the stored document", step_tamper_document),
    ("15", "Attack: tamper with the share", step_tamper_share),
    ("16", "Inspect the account database", step_show_database),
    ("17", "Inspect server storage", step_show_storage),
    ("18", "Inspect the encrypted document bytes", step_show_encrypted_bytes),
    ("19", "Attack: substitute Layla's public key", step_substitute_key),
    ("20", "Change Layla's password", step_change_password),
    ("21", "Log both users out", step_logout),
    ("22", "Show current state", step_status),
]

ACTIONS = {key: function for key, _label, function in MENU}


def print_menu():
    print()
    print("SecureVault demo".center(78, " "))
    print("-" * 78)
    left = MENU[:11]
    right = MENU[11:]
    for index in range(len(left)):
        a = left[index]
        first = f"  {a[0]:>2}  {a[1]}"
        if index < len(right):
            b = right[index]
            print(f"{first:<42}{b[0]:>3}  {b[1]}")
        else:
            print(first)
    print("-" * 78)
    print("   0  quit")


def main():
    print(__doc__)
    while True:
        print_menu()
        try:
            choice = input("\nstep> ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "0"

        if choice == "0":
            if server_is_running():
                state["stop_event"].set()
                state["server_thread"].join(timeout=3.0)
            print("\nDone.")
            return

        action = ACTIONS.get(choice)
        if action is None:
            print("Unknown step.")
            continue

        try:
            action()
        except Exception as error:
            print()
            print(f"    step failed: {error!r}")


if __name__ == "__main__":
    main()
