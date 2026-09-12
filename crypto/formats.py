def pack_str(data: bytes) -> bytes:
    length_prefix = len(data).to_bytes(4, "big")
    return length_prefix + data


def unpack_str(buffer: bytes, offset: int):
    length = int.from_bytes(buffer[offset:offset + 4], "big")
    start = offset + 4
    end = start + length
    data = buffer[start:end]
    return data, end


class Document:

    VERSION = 1
    TYPE = 4

    def __init__(self, document_id, owner_id, filename, mime_type, size, timestamp, nonce, ciphertext, tag):
        self.document_id = document_id
        self.owner_id = owner_id
        self.filename = filename
        self.mime_type = mime_type
        self.size = size
        self.timestamp = timestamp
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag

    def get_aad(self) -> bytes:
        return (
            self.document_id
            + pack_str(self.owner_id)
            + pack_str(self.filename)
            + pack_str(self.mime_type)
            + self.size.to_bytes(8, "big")
            + self.timestamp.to_bytes(8, "big")
        )

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return (
            header
            + self.get_aad()
            + self.nonce
            + pack_str(self.ciphertext)
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Document object (wrong version/type byte)")

        offset = 2
        document_id = data[offset:offset + 16]
        offset += 16

        owner_id, offset = unpack_str(data, offset)
        filename, offset = unpack_str(data, offset)
        mime_type, offset = unpack_str(data, offset)

        size = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        timestamp = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8

        nonce = data[offset:offset + 12]
        offset += 12

        ciphertext, offset = unpack_str(data, offset)

        tag = data[offset:offset + 16]
        offset += 16

        return cls(document_id, owner_id, filename, mime_type, size, timestamp, nonce, ciphertext, tag)


class Credential:

    VERSION = 1
    TYPE = 1

    def __init__(self, user_id, salt, argon2_params, auth_value):
        self.user_id = user_id
        self.salt = salt
        self.argon2_params = argon2_params
        self.auth_value = auth_value

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return (
            header
            + pack_str(self.user_id)
            + self.salt
            + pack_str(self.argon2_params)
            + self.auth_value
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Credential object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        salt = data[offset:offset + 16]
        offset += 16

        argon2_params, offset = unpack_str(data, offset)

        auth_value = data[offset:offset + 32]
        offset += 32

        return cls(user_id, salt, argon2_params, auth_value)


class PublicKey:

    VERSION = 1
    TYPE = 2

    def __init__(self, user_id, p256_public_key, rsa_modulus, rsa_public_exponent):
        self.user_id = user_id
        self.p256_public_key = p256_public_key
        self.rsa_modulus = rsa_modulus
        self.rsa_public_exponent = rsa_public_exponent

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return (
            header
            + pack_str(self.user_id)
            + self.p256_public_key
            + self.rsa_modulus
            + self.rsa_public_exponent
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid PublicKey object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        p256_public_key = data[offset:offset + 65]
        offset += 65

        rsa_modulus = data[offset:offset + 384]
        offset += 384

        rsa_public_exponent = data[offset:offset + 3]
        offset += 3

        return cls(user_id, p256_public_key, rsa_modulus, rsa_public_exponent)


class WrappedPrivateKey:

    VERSION = 1
    TYPE = 3

    def __init__(self, user_id, nonce, ciphertext, tag):
        self.user_id = user_id
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return (
            header
            + pack_str(self.user_id)
            + self.nonce
            + pack_str(self.ciphertext)
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid WrappedPrivateKey object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        nonce = data[offset:offset + 12]
        offset += 12

        ciphertext, offset = unpack_str(data, offset)

        tag = data[offset:offset + 16]
        offset += 16

        return cls(user_id, nonce, ciphertext, tag)


class Share:

    VERSION = 1
    TYPE = 5

    def __init__(self, document_id, sender_id, recipient_id, sender_fingerprint,
                 recipient_fingerprint, sequence_number, timestamp,
                 ephemeral_public_key, wrapped_document_key, signature):
        self.document_id = document_id
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.sender_fingerprint = sender_fingerprint
        self.recipient_fingerprint = recipient_fingerprint
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ephemeral_public_key = ephemeral_public_key
        self.wrapped_document_key = wrapped_document_key
        self.signature = signature

    def signed_bytes(self) -> bytes:
        return (
            self.document_id
            + pack_str(self.sender_id)
            + pack_str(self.recipient_id)
            + self.sender_fingerprint
            + self.recipient_fingerprint
            + self.sequence_number.to_bytes(8, "big")
            + self.timestamp.to_bytes(8, "big")
            + self.ephemeral_public_key
            + pack_str(self.wrapped_document_key)
        )

    def to_bytes(self) -> bytes:
        header = bytes([self.VERSION, self.TYPE])
        return (
            header
            + self.signed_bytes()
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Share object (wrong version/type byte)")

        offset = 2
        document_id = data[offset:offset + 16]
        offset += 16

        sender_id, offset = unpack_str(data, offset)
        recipient_id, offset = unpack_str(data, offset)

        sender_fingerprint = data[offset:offset + 32]
        offset += 32
        recipient_fingerprint = data[offset:offset + 32]
        offset += 32

        sequence_number = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
        timestamp = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8

        ephemeral_public_key = data[offset:offset + 65]
        offset += 65

        wrapped_document_key, offset = unpack_str(data, offset)

        signature = data[offset:offset + 384]
        offset += 384

        return cls(document_id, sender_id, recipient_id, sender_fingerprint,
                   recipient_fingerprint, sequence_number, timestamp,
                   ephemeral_public_key, wrapped_document_key, signature)
