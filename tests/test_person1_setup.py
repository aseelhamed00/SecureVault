import importlib
from pathlib import Path
from tempfile import TemporaryDirectory


def test_project_imports():
    modules = [
        "crypto.rsa_pss",
        "crypto.hmac_hkdf",
        "accounts",
        "private_keys",
        "benchmarks.passwords",
    ]

    for name in modules:
        importlib.import_module(name)


def test_dependencies():
    for name in ["argon2", "pytest", "cryptography"]:
        importlib.import_module(name)


def test_temporary_storage():
    with TemporaryDirectory() as folder:
        directory = Path(folder)
        test_file = directory / "test_account.txt"

        test_file.write_text("temporary test data", encoding="utf-8")

        assert test_file.read_text(encoding="utf-8") == "temporary test data"

        test_file.unlink()
        assert not test_file.exists()

    assert not directory.exists()