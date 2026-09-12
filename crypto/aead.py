def pad16(data):
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - len(data) % 16)


def chacha20_poly1305_encrypt(key, nonce, plaintext, aad):
  ]    poly1305_key = chacha20_block(key, nonce, 0)[:32]

    ciphertext = chacha20_encrypt(key, nonce, plaintext, 1)

    aad_len = len(aad).to_bytes(8, 'little')
    ciphertext_len = len(ciphertext).to_bytes(8, 'little')

    poly1305_input = pad16(aad) + pad16(ciphertext) + aad_len + ciphertext_len

    tag = poly1305(poly1305_key, poly1305_input)

    return ciphertext + tag


def chacha20_poly1305_decrypt(key, nonce, ciphertext_with_tag, aad):
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    poly1305_key = chacha20_block(key, nonce, 0)[:32]

    aad_len = len(aad).to_bytes(8, 'little')
    ciphertext_len = len(ciphertext).to_bytes(8, 'little')

    poly1305_input = pad16(aad) + pad16(ciphertext) + aad_len + ciphertext_len

    expected_tag = poly1305(poly1305_key, poly1305_input)
    if tag != expected_tag:
        raise ValueError("Invalid tag - message tampered")

    plaintext = chacha20_encrypt(key, nonce, ciphertext, 1)

    return plaintext
