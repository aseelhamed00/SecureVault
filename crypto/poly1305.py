def poly1305_clamp(r):
    r = bytearray(r)
    r[3] &= 0x0F
    r[7] &= 0x0F
    r[11] &= 0x0F
    r[15] &= 0x0F
    r[4] &= 0xFC
    r[8] &= 0xFC
    r[12] &= 0xFC
    return bytes(r)


def poly1305(key, message):
    r = key[0:16]
    s = key[16:32]

    r = poly1305_clamp(r)
    r_value = int.from_bytes(r, 'little')
    s_value = int.from_bytes(s, 'little')

    p = 2 ** 130 - 5
    acc = 0

    for i in range(0, len(message), 16):
        block = message[i:i + 16]

        padded_block = block + b'\x01'
        if len(padded_block) < 17:
            padded_block = padded_block + b'\x00' * (17 - len(padded_block))

        block_value = int.from_bytes(padded_block, 'little')
        acc = ((acc + block_value) * r_value) % p

    tag = (acc + s_value) % 2 ** 128
    return tag.to_bytes(16, 'little')
