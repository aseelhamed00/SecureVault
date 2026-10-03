"""
SecureVault - full system test runner.

Runs:
  1. The entire existing pytest suite.
  2. A real Layla -> Omar application flow using the real server.py,
     client.py, transport.py, account code, sharing code, trust and freshness.
  3. Negative/security cases: plaintext exposure, document tampering,
     share tampering, replay, and TOFU key substitution.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_full_pytest() -> None:
    """Run every repository test with the crypto package on PYTHONPATH."""
    banner("PHASE 1: COMPLETE EXISTING TEST SUITE")

    env = os.environ.copy()
    paths = [str(PROJECT_ROOT), str(PROJECT_ROOT / "crypto")]
    old = env.get("PYTHONPATH")
    if old:
        paths.append(old)
    env["PYTHONPATH"] = os.pathsep.join(paths)

    cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
    print("$", " ".join(cmd))
    result = subprocess.run(cmd, cwd=PROJECT_ROOT, env=env)

    if result.returncode != 0:
        raise AssertionError(
            f"The existing pytest suite failed with exit code {result.returncode}."
        )

    print("\n[PASS] Entire existing pytest suite passed.")


def start_server(workdir: Path):
    server_script = PROJECT_ROOT / "server.py"
    process = subprocess.Popen(
        [sys.executable, str(server_script)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.5)
    if process.poll() is not None:
        stdout, stderr = process.communicate(timeout=3)
        raise AssertionError(
            "Server failed to start.\nSTDOUT:\n"
            + stdout
            + "\nSTDERR:\n"
            + stderr
        )
    return process


def stop_server(process) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def wait_for_file(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {path}")


def latest_file(directory: Path) -> Path:
    files = sorted(directory.glob("*.obj"), key=lambda p: p.stat().st_mtime_ns)
    check(bool(files), f"No .obj files found in {directory}")
    return files[-1]


def application_flow() -> None:
    """Run the real application path and attack tests."""
    banner("PHASE 2: REAL LAYLA -> OMAR APPLICATION TEST")

    # Import after the project root is known.
    sys.path.insert(0, str(PROJECT_ROOT))

    import client
    import server
    import transport

    with tempfile.TemporaryDirectory(prefix="securevault_full_test_") as raw:
        root = Path(raw)
        old_cwd = Path.cwd()
        os.chdir(root)

        alice_dir = root / "client_layla"
        omar_dir = root / "client_omar"
        alice = "layla"
        omar = "omar"
        alice_password = "Layla-test-password-123!"
        omar_password = "Omar-test-password-123!"

        process = None
        try:
            process = start_server(root)

            # 2.1 ACCOUNT CREATION
            print("[1/13] Registering Layla...")
            layla = client.cmd_register(
                alice, alice_password, client_dir=alice_dir, timeout=30
            )
            check(layla is not None, "Layla registration failed")

            print("[2/13] Registering Omar...")
            omar_result = client.cmd_register(
                omar, omar_password, client_dir=omar_dir, timeout=30
            )
            check(omar_result is not None, "Omar registration failed")
            check(layla["fingerprint"] != omar_result["fingerprint"],
                  "Two users unexpectedly have the same fingerprint")

            # 2.2 LOGIN
            print("[3/13] Logging both users in...")
            layla_login = client.cmd_login(
                alice, alice_password, client_dir=alice_dir, timeout=30
            )
            omar_login = client.cmd_login(
                omar, omar_password, client_dir=omar_dir, timeout=30
            )
            check(layla_login is not None, "Layla login failed")
            check(omar_login is not None, "Omar login failed")
            check((alice_dir / "session.json").exists(),
                  "Layla session file was not created")
            check((omar_dir / "session.json").exists(),
                  "Omar session file was not created")

            # 2.3 UPLOAD
            plaintext = (
                b"SecureVault FULL SYSTEM TEST\n"
                b"This file must be confidential and integrity protected.\n"
                b"Layla -> Omar test payload.\n"
            )
            source = root / "secret.txt"
            source.write_bytes(plaintext)

            print("[4/13] Layla uploads an encrypted document...")
            document_id = client.cmd_upload(
                str(source), alice, client_dir=alice_dir
            )
            check(document_id is not None, "Upload failed")

            document_path = (
                root / "server_storage" / "documents" / f"{document_id.hex()}.obj"
            )
            wait_for_file(document_path)

            server_document = document_path.read_bytes()
            check(plaintext not in server_document,
                  "SECURITY FAILURE: plaintext appears in server document")

            # 2.4 SHARE
            print("[5/13] Layla creates and sends a real Share to Omar...")
            share = client.cmd_share(
                document_id.hex(),
                alice,
                omar,
                client_dir=alice_dir,
                timeout=30,
            )
            check(share is not None, "Share creation failed")

            share_dir = root / "server_storage" / "shares" / omar
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if list(share_dir.glob("*.obj")):
                    break
                time.sleep(0.05)
            check(bool(list(share_dir.glob("*.obj"))),
                  "Share never reached server storage")

            # 2.5 RECEIVE
            print("[6/13] Omar receives/verifies/unwraps the Share...")
            received = client.cmd_receive(
                omar, client_dir=omar_dir, timeout=30
            )
            check(received is not None, "Receive failed")
            check(document_id.hex() in received,
                  "Omar did not accept Layla's document share")

            # 2.6 DOWNLOAD + AEAD VERIFICATION
            print("[7/13] Omar downloads and decrypts the document...")
            output = root / "omar-recovered.txt"
            downloaded = client.cmd_download(
                document_id.hex(),
                omar,
                str(output),
                client_dir=omar_dir,
                timeout=30,
            )
            check(downloaded is not None, "Omar download failed")
            check(output.read_bytes() == plaintext,
                  "Recovered plaintext does not match original plaintext")

            # 2.7 REPLAY
            print("[8/13] Replaying the already-accepted Share...")
            replay_result = client.cmd_receive(
                omar, client_dir=omar_dir, timeout=30
            )
            check(replay_result == [],
                  "SECURITY FAILURE: replayed Share was accepted")

            # 2.8 DOCUMENT TAMPERING
            print("[9/13] Tampering with the stored document ciphertext...")
            original_document = document_path.read_bytes()
            tampered_document = bytearray(original_document)
            check(len(tampered_document) > 20, "Document object unexpectedly tiny")
            tampered_document[-1] ^= 0x01
            document_path.write_bytes(tampered_document)

            tampered_output = root / "tampered-output.txt"
            result = client.cmd_download(
                document_id.hex(),
                omar,
                str(tampered_output),
                client_dir=omar_dir,
                timeout=30,
            )
            check(result is None,
                  "SECURITY FAILURE: tampered document was accepted")
            document_path.write_bytes(original_document)

            # 2.9 SHARE SIGNATURE TAMPERING
            print("[10/13] Creating a fresh Share and tampering with its bytes...")

            shares_dir = root / "server_storage" / "shares" / omar

            # Snapshot the shares that already existed before creating the new one.
            before_shares = set(shares_dir.glob("*.obj"))

            # Create an actual new Share.
            fresh_share = client.cmd_share(
                document_id.hex(),
                alice,
                omar,
                client_dir=alice_dir,
                timeout=30,
            )

            check(fresh_share is not None, "Could not create fresh Share")

            # Wait until a new server-side Share file appears.
            deadline = time.time() + 30
            new_share_path = None

            while time.time() < deadline:
                current_shares = set(shares_dir.glob("*.obj"))
                new_files = current_shares - before_shares

                if new_files:
                    # There should be exactly one newly-created Share.
                    check(
                        len(new_files) == 1,
                        f"Expected exactly one new Share, found {len(new_files)}",
                    )
                    new_share_path = next(iter(new_files))
                    break

                time.sleep(0.05)

            check(new_share_path is not None, "Timed out waiting for fresh Share")

            # Read the actual newly-created Share and tamper with its bytes.
            original_share = new_share_path.read_bytes()
            tampered_share = bytearray(original_share)

            check(
                len(tampered_share) > 0,
                "Fresh Share file is unexpectedly empty",
            )

            # Flip one byte in the Share.
            tampered_share[-1] ^= 0x01

            new_share_path.write_bytes(bytes(tampered_share))

            # Omar should reject the tampered Share.
            result = client.cmd_receive(
                omar,
                client_dir=omar_dir,
                timeout=30,
            )

            check(
                fresh_share.document_id.hex() not in result,
                "SECURITY FAILURE: tampered Share was accepted",
            )

            print("Share signature tampering rejected: OK")
            # 2.10 TOFU KEY SUBSTITUTION
            print("[11/13] Testing TOFU public-key substitution detection...")

            import sqlite3

            account_db = root / "server_private" / "accounts.db"

            # Read the legitimate Layla and Omar public keys from the server DB.
            with sqlite3.connect(account_db) as conn:
                row = conn.execute(
                    "SELECT value FROM records WHERE user_id = ? AND kind = ?",
                    (alice.encode(), "public_key"),
                ).fetchone()
                check(row is not None, "Layla public key not found in AccountStore")
                original_layla_public = row[0]

                row = conn.execute(
                    "SELECT value FROM records WHERE user_id = ? AND kind = ?",
                    (omar.encode(), "public_key"),
                ).fetchone()
                check(row is not None, "Omar public key not found in AccountStore")
                substituted_public = row[0]

            check(
                original_layla_public != substituted_public,
                "Layla and Omar unexpectedly have identical public keys",
            )

            # Replace Layla's server-side public key with Omar's public key.
            with sqlite3.connect(account_db) as conn:
                conn.execute(
                    "UPDATE records SET value = ? "
                    "WHERE user_id = ? AND kind = ?",
                    (
                        substituted_public,
                        alice.encode(),
                        "public_key",
                    ),
                )
                conn.commit()

            try:
                # Omar already pinned Layla's original public key during Phase 6.
                # The server now returns Omar's key when asked for Layla's key.
                # The TOFU check must therefore reject the Share.
                result = client.cmd_receive(
                    omar,
                    client_dir=omar_dir,
                    timeout=30,
                )

                check(
                    result == [],
                    "SECURITY FAILURE: TOFU key substitution was accepted",
                )

            finally:
                # Restore Layla's legitimate key so the server state is clean.
                with sqlite3.connect(account_db) as conn:
                    conn.execute(
                        "UPDATE records SET value = ? "
                        "WHERE user_id = ? AND kind = ?",
                        (
                            original_layla_public,
                            alice.encode(),
                            "public_key",
                        ),
                    )
                    conn.commit()

            print("TOFU public-key substitution rejected: OK")

            # 2.11 SERVER CONFIDENTIALITY CHECK
            print("[12/13] Checking that server storage has no raw plaintext...")
            all_server_files = bytearray()
            for folder in (
                root / "server_storage",
                root / "server_private",
            ):
                if folder.exists():
                    for path in folder.rglob("*"):
                        if path.is_file():
                            all_server_files.extend(path.read_bytes())
            check(plaintext not in bytes(all_server_files),
                  "SECURITY FAILURE: plaintext found in server-side files")

            # 2.12 LOGOUT / SESSION REMOVAL
            print("[13/13] Logging users out and checking local sessions...")
            layla_logout = client.cmd_logout(
                alice, client_dir=alice_dir, timeout=30
            )
            omar_logout = client.cmd_logout(
                omar, client_dir=omar_dir, timeout=30
            )
            check(layla_logout is not None, "Layla logout failed")
            check(omar_logout is not None, "Omar logout failed")
            check(not (alice_dir / "session.json").exists(),
                  "Layla session file survived logout")
            check(not (omar_dir / "session.json").exists(),
                  "Omar session file survived logout")

            print("\n[PASS] Real application flow and security attacks passed.")

        finally:
            stop_server(process)
            os.chdir(old_cwd)


def main() -> int:
    started = time.monotonic()
    try:
        run_full_pytest()
        application_flow()
    except Exception as exc:
        banner("FULL SYSTEM TEST FAILED")
        print(type(exc).__name__ + ":", exc)
        print("\nFix the failure above, then rerun this same script.")
        return 1

    elapsed = time.monotonic() - started
    banner("FULL SYSTEM TEST PASSED")
    print(f"Everything tested successfully. Runtime: {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
