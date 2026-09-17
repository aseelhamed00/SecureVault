import os
import uuid
import time

SHARED_ROOT = "shared_network"
SERVER_INBOX = "server"


def _inbox_path(recipient_id: str) -> str:
    if not recipient_id or "/" in recipient_id or "\\" in recipient_id or recipient_id in (".", ".."):
        raise ValueError("Invalid recipient_id")
    return os.path.join(SHARED_ROOT, recipient_id)


def _ensure_inbox(recipient_id: str) -> str:
    path = _inbox_path(recipient_id)
    os.makedirs(path, exist_ok=True)
    return path


def send_message(recipient_id: str, payload: bytes) -> str:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    inbox = _ensure_inbox(recipient_id)

    msg_id = uuid.uuid4().hex
    filename = f"{msg_id}.msg"
    final_path = os.path.join(inbox, filename)
    tmp_path = final_path + ".tmp"

    with open(tmp_path, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())

    os.rename(tmp_path, final_path)  # atomic on POSIX

    return filename


def poll_messages(recipient_id: str) -> list[tuple[str, bytes]]:
    inbox = _ensure_inbox(recipient_id)

    results = []
    for fname in sorted(os.listdir(inbox)):
        if not fname.endswith(".msg"):
            continue
        path = os.path.join(inbox, fname)
        try:
            with open(path, "rb") as f:
                results.append((fname, f.read()))
        except FileNotFoundError:
            continue

    return results


def consume_message(recipient_id: str, filename: str) -> None:
    inbox = _inbox_path(recipient_id)
    path = os.path.join(inbox, filename)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def wait_for_message(recipient_id: str, timeout: float = 10.0, interval: float = 0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msgs = poll_messages(recipient_id)
        if msgs:
            return msgs[0]
        time.sleep(interval)
    return None
