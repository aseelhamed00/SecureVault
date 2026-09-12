import math
import secrets

from crypto.sha256 import sha256

RSA_BITS = 3072
PUBLIC_EXPONENT = 65537
PRIME_ROUNDS = 64
HASH_LEN = 32
SALT_LEN = 32


def is_probable_prime(n, rounds=PRIME_ROUNDS):
    if not isinstance(rounds, int) or rounds < 1:
        raise ValueError("rounds must be a positive integer")

    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits, e=PUBLIC_EXPONENT):
    if not isinstance(bits, int) or bits < 3:
        raise ValueError("bits must be an integer of at least 3")

    if not isinstance(e, int) or e < 3 or e % 2 == 0:
        raise ValueError("e must be an odd integer of at least 3")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if math.gcd(e, candidate - 1) != 1:
            continue

        if is_probable_prime(candidate):
            return candidate


def rsa_keygen():
    e = PUBLIC_EXPONENT

    while True:
        p = generate_prime(RSA_BITS // 2, e)
        q = generate_prime(RSA_BITS // 2, e)

        if p == q:
            continue

        n = p * q

        if n.bit_length() != RSA_BITS:
            continue

        lambda_n = math.lcm(p - 1, q - 1)

        if math.gcd(e, lambda_n) != 1:
            continue

        d = pow(e, -1, lambda_n)

        if (e * d) % lambda_n != 1:
            raise ValueError("Invalid RSA key")

        private_key = {
            "n": n,
            "e": e,
            "d": d,
            "p": p,
            "q": q,
        }

        public_key = {
            "n": n,
            "e": e,
        }

        return private_key, public_key


def i2osp(value, length):
    if not isinstance(value, int) or value < 0:
        raise ValueError("value must be a non-negative integer")

    if not isinstance(length, int) or length < 0:
        raise ValueError("length must be a non-negative integer")

    if value >= 1 << (8 * length):
        raise ValueError("integer too large for the requested length")

    return value.to_bytes(length, "big")


def os2ip(data):
    return int.from_bytes(data, "big")


def mgf1(seed, length):
    if not isinstance(length, int) or length < 0:
        raise ValueError("length must be a non-negative integer")

    if length > (1 << 32) * HASH_LEN:
        raise ValueError("mask too long")

    blocks = []
    counter = 0
    produced = 0

    while produced < length:
        blocks.append(sha256(bytes(seed) + i2osp(counter, 4)))
        produced += HASH_LEN
        counter += 1

    return b"".join(blocks)[:length]


def pss_encode(message, em_bits, salt=None):
    em_len = (em_bits + 7) // 8

    if salt is None:
        salt = secrets.token_bytes(SALT_LEN)

    if em_len < HASH_LEN + len(salt) + 2:
        raise ValueError("encoding error")

    m_hash = sha256(message)
    h = sha256(b"\x00" * 8 + m_hash + bytes(salt))

    padding = b"\x00" * (em_len - len(salt) - HASH_LEN - 2)
    db = padding + b"\x01" + bytes(salt)
    db_mask = mgf1(h, em_len - HASH_LEN - 1)

    masked = bytes(a ^ b for a, b in zip(db, db_mask))
    unused = 8 * em_len - em_bits

    if unused:
        masked = bytes([masked[0] & (0xFF >> unused)]) + masked[1:]

    return masked + h + b"\xbc"


def pss_decode(message, em, em_bits, salt_len=SALT_LEN):
    em_len = (em_bits + 7) // 8

    if len(em) != em_len:
        return False

    if em_len < HASH_LEN + salt_len + 2:
        return False

    if em[-1] != 0xBC:
        return False

    masked = em[: em_len - HASH_LEN - 1]
    h = em[em_len - HASH_LEN - 1 : em_len - 1]
    unused = 8 * em_len - em_bits

    if unused and masked[0] >> (8 - unused):
        return False

    db_mask = mgf1(h, em_len - HASH_LEN - 1)
    db = bytes(a ^ b for a, b in zip(masked, db_mask))

    if unused:
        db = bytes([db[0] & (0xFF >> unused)]) + db[1:]

    split = em_len - HASH_LEN - salt_len - 2

    if db[:split] != b"\x00" * split:
        return False

    if db[split] != 0x01:
        return False

    salt = db[split + 1 :]
    m_hash = sha256(message)
    expected = sha256(b"\x00" * 8 + m_hash + salt)

    return secrets.compare_digest(h, expected)


def pss_sign(private_key, message):
    n = private_key["n"]
    d = private_key["d"]

    k = (n.bit_length() + 7) // 8
    salt = secrets.token_bytes(SALT_LEN)
    em = pss_encode(message, n.bit_length() - 1, salt)
    m = os2ip(em)

    if m >= n:
        raise ValueError("message representative out of range")

    return i2osp(pow(m, d, n), k)


def pss_verify(public_key, message, signature):
    n = public_key["n"]
    e = public_key["e"]

    k = (n.bit_length() + 7) // 8

    if not isinstance(signature, (bytes, bytearray)) or len(signature) != k:
        return False

    s = os2ip(signature)

    if s >= n:
        return False

    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8

    try:
        em = i2osp(pow(s, e, n), em_len)
    except ValueError:
        return False

    return pss_decode(message, em, em_bits)