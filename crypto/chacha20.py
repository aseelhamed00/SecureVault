def left_rotate(x, n):
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

CHACHA20_CONSTANTS = [
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574
]

def quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d = left_rotate(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF
    b = left_rotate(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF
    d = left_rotate(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF
    b = left_rotate(b ^ c, 7)
    return a, b, c, d

def chacha20_inner_block(state):
    working = state.copy()

    for _ in range(10):
        # column rounds
        working[0], working[4], working[8], working[12] = quarter_round(
            working[0], working[4], working[8], working[12]
        )
        working[1], working[5], working[9], working[13] = quarter_round(
            working[1], working[5], working[9], working[13]
        )
        working[2], working[6], working[10], working[14] = quarter_round(
            working[2], working[6], working[10], working[14]
        )
        working[3], working[7], working[11], working[15] = quarter_round(
            working[3], working[7], working[11], working[15]
        )

        # diagonal rounds
        working[0], working[5], working[10], working[15] = quarter_round(
            working[0], working[5], working[10], working[15]
        )
        working[1], working[6], working[11], working[12] = quarter_round(
            working[1], working[6], working[11], working[12]
        )
        working[2], working[7], working[8], working[13] = quarter_round(
            working[2], working[7], working[8], working[13]
        )
        working[3], working[4], working[9], working[14] = quarter_round(
            working[3], working[4], working[9], working[14]
        )

    return working

def chacha20_block(key, nonce, counter):
    state = [
        CHACHA20_CONSTANTS[0],
        CHACHA20_CONSTANTS[1],
        CHACHA20_CONSTANTS[2],
        CHACHA20_CONSTANTS[3],

        int.from_bytes(key[0:4], 'little'),
        int.from_bytes(key[4:8], 'little'),
        int.from_bytes(key[8:12], 'little'),
        int.from_bytes(key[12:16], 'little'),

        int.from_bytes(key[16:20], 'little'),
        int.from_bytes(key[20:24], 'little'),
        int.from_bytes(key[24:28], 'little'),
        int.from_bytes(key[28:32], 'little'),

        counter,

        int.from_bytes(nonce[0:4], 'little'),
        int.from_bytes(nonce[4:8], 'little'),
        int.from_bytes(nonce[8:12], 'little')
    ]

    working = chacha20_inner_block(state)

    out = bytearray()
    for i in range(16):
        out.extend(((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, 'little'))

    return bytes(out)

def chacha20_encrypt(key, nonce, plaintext, counter=0):
    """Encrypt plaintext with ChaCha20 starting from given counter."""
    ciphertext = bytearray()
    current_counter = counter

    while len(ciphertext) < len(plaintext):
        keystream = chacha20_block(key, nonce, current_counter)

        remaining = len(plaintext) - len(ciphertext)
        if remaining < 64:
            keystream = keystream[:remaining]

        for i in range(len(keystream)):
            ciphertext.append(plaintext[len(ciphertext)] ^ keystream[i])

        current_counter += 1

    return bytes(ciphertext)
