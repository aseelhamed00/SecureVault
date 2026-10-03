import time
from crypto.p256 import p256_keygen, ecdh


def measure_keygen():
    start = time.perf_counter()

    private_key, public_key = p256_keygen()

    end = time.perf_counter()

    return end - start


def measure_ecdh():
    private_key1, public_key1 = p256_keygen()
    private_key2, public_key2 = p256_keygen()

    start = time.perf_counter()

    shared1 = ecdh(private_key1, public_key2)

    end = time.perf_counter()

    shared2 = ecdh(private_key2, public_key1)

    assert shared1 == shared2

    return end - start


def main():
    runs = 10

    keygen_times = []
    ecdh_times = []

    for i in range(runs):
        keygen_times.append(measure_keygen())
        ecdh_times.append(measure_ecdh())

    average_keygen = sum(keygen_times) / runs
    average_ecdh = sum(ecdh_times) / runs

    print("P-256 benchmark")
    print("----------------")
    print("Runs:", runs)
    print("Average key generation:", average_keygen, "seconds")
    print("Average ECDH:", average_ecdh, "seconds")


if __name__ == "__main__":
    main()