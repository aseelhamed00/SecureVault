import json
import os
import platform
import random
import secrets
import statistics
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from accounts import derive_password_values

TARGET = 0.25
REPEATS = 5
OUT_DIR = Path(__file__).resolve().parent


def main():
    password = "Test-only-password-123!"
    salt = secrets.token_bytes(16)
    candidates = [
        {"memory_cost": memory, "time_cost": iterations, "parallelism": lanes,
         "hash_len": 32, "version": 19}
        for memory in (65536, 131072)
        for iterations in (2, 3)
        for lanes in (1, 4)
    ]
    rows = [{"parameters": params, "seconds": []} for params in candidates]
    print("Measuring Argon2id + two HKDF derivations; memory units: KiB", flush=True)
    for row in rows:
        derive_password_values(password, salt, row["parameters"])
    for round_number in range(REPEATS):
        order = list(range(len(rows)))
        random.shuffle(order)
        for index in order:
            row = rows[index]
            start = time.perf_counter()
            derive_password_values(password, salt, row["parameters"])
            elapsed = time.perf_counter() - start
            row["seconds"].append(elapsed)
        print(f"Round {round_number + 1}/{REPEATS} finished", flush=True)
    for row in rows:
        row["median_seconds"] = statistics.median(row["seconds"])
        row["min_seconds"] = min(row["seconds"])
        row["max_seconds"] = max(row["seconds"])
        p = row["parameters"]
        print(f"m={p['memory_cost']} t={p['time_cost']} p={p['parallelism']} "
              f"median={row['median_seconds']:.4f}s", flush=True)
    selected = min(rows, key=lambda row: abs(row["median_seconds"] - TARGET))
    reason = (
        "Selected the candidate with median full-derivation time closest to 0.25 s "
        "among the eight measured candidates (64/128 MiB, 2/3 iterations, 1/4 lanes). "
        "This is a latency-based choice within this candidate set, not a proof of "
        "optimal security or a guaranteed runtime."
    )
    report = {
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "hardware": {
            "system": platform.platform(),
            "cpu": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "Unavailable"),
            "architecture": platform.machine(),
            "logical_cpus": os.cpu_count(),
        },
        "python": platform.python_version(),
        "argon2_cffi": version("argon2-cffi"),
        "target_seconds": TARGET,
        "repeats_per_candidate": REPEATS,
        "warmups_per_candidate": 1,
        "measurement": "Argon2id plus two HKDF calls; excludes disk I/O and account/network operations",
        "method": "Sequential calls; randomized candidate order each round; same test password and salt",
        "candidates": rows,
        "selected_parameters": selected["parameters"],
        "selected_median_seconds": selected["median_seconds"],
        "selection_reason": reason,
    }
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "password_measurements.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "password_config.json").write_text(
        json.dumps(selected["parameters"], indent=2) + "\n", encoding="utf-8")
    print("Selected:", selected["parameters"])
    print(reason)
    print("Saved benchmarks/password_measurements.json and benchmarks/password_config.json")


if __name__ == "__main__":
    main()
