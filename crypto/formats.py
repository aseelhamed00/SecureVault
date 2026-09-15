def pack_str(data: bytes) -> bytes:
    length_prefix = len(data).to_bytes(4, "big")
    return length_prefix + data


def unpack_str(buffer: bytes, offset: int):
    if offset + 4 > len(buffer):
        raise ValueError("Malformed object")
    length = int.from_bytes(buffer[offset:offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(buffer):
        raise ValueError("Malformed object")
    data = buffer[start:end]
    return data, end


def take_fixed(buffer: bytes, offset: int, size: int):
    end = offset + size
    if end > len(buffer):
        raise ValueError("Malformed object")
    return buffer[offset:end], end


def check_end(buffer: bytes, offset: int):
    if offset != len(buffer):
        raise ValueError("Malformed object")



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
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Document object (wrong version/type byte)")

        offset = 2
        document_id, offset = take_fixed(data, offset, 16)

        owner_id, offset = unpack_str(data, offset)
        filename, offset = unpack_str(data, offset)
        mime_type, offset = unpack_str(data, offset)

        size_bytes, offset = take_fixed(data, offset, 8)
        size = int.from_bytes(size_bytes, "big")
        timestamp_bytes, offset = take_fixed(data, offset, 8)
        timestamp = int.from_bytes(timestamp_bytes, "big")

        nonce, offset = take_fixed(data, offset, 12)

        ciphertext, offset = unpack_str(data, offset)

        tag, offset = take_fixed(data, offset, 16)

        check_end(data, offset)

        return cls(document_id, owner_id, filename, mime_type, size, timestamp, nonce, ciphertext, tag)


class Credential:

    VERSION = 1
    TYPE = 1

    def __init__(self, user_id, salt, argon2_params, auth_value):
        self.user_id = user_id
        self.salt = salt
        self.argon2_params = argon2_params
        self.auth_value = auth_value

    def get_aad(self) -> bytes:
        return bytes([self.VERSION, self.TYPE]) + pack_str(self.user_id)

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
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Credential object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        salt, offset = take_fixed(data, offset, 16)

        argon2_params, offset = unpack_str(data, offset)

        auth_value, offset = take_fixed(data, offset, 32)

        check_end(data, offset)

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
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid PublicKey object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        p256_public_key, offset = take_fixed(data, offset, 65)

        rsa_modulus, offset = take_fixed(data, offset, 384)

        rsa_public_exponent, offset = take_fixed(data, offset, 3)

        check_end(data, offset)

        return cls(user_id, p256_public_key, rsa_modulus, rsa_public_exponent)


class WrappedPrivateKey:

    VERSION = 1
    TYPE = 3

    def __init__(self, user_id, nonce, ciphertext, tag):
        self.user_id = user_id
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag

    def get_aad(self) -> bytes:
        return bytes([self.VERSION, self.TYPE]) + pack_str(self.user_id)

    def to_bytes(self) -> bytes:
        if not isinstance(self.user_id, bytes):
            raise ValueError("User ID must be bytes")

        if not isinstance(self.nonce, bytes) or len(self.nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")

        if not isinstance(self.ciphertext, bytes):
            raise ValueError("Ciphertext must be bytes")

        if not isinstance(self.tag, bytes) or len(self.tag) != 16:
            raise ValueError("Tag must be 16 bytes")

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
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid WrappedPrivateKey object (wrong version/type byte)")

        offset = 2
        user_id, offset = unpack_str(data, offset)

        nonce, offset = take_fixed(data, offset, 12)

        ciphertext, offset = unpack_str(data, offset)

        tag, offset = take_fixed(data, offset, 16)

        check_end(data, offset)

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
        if len(data) < 2:
            raise ValueError("Malformed object")
        version = data[0]
        type_ = data[1]
        if version != cls.VERSION or type_ != cls.TYPE:
            raise ValueError("Not a valid Share object (wrong version/type byte)")

        offset = 2
        document_id, offset = take_fixed(data, offset, 16)

        sender_id, offset = unpack_str(data, offset)
        recipient_id, offset = unpack_str(data, offset)

        sender_fingerprint, offset = take_fixed(data, offset, 32)
        recipient_fingerprint, offset = take_fixed(data, offset, 32)

        sequence_number_bytes, offset = take_fixed(data, offset, 8)
        sequence_number = int.from_bytes(sequence_number_bytes, "big")
        timestamp_bytes, offset = take_fixed(data, offset, 8)
        timestamp = int.from_bytes(timestamp_bytes, "big")

        ephemeral_public_key, offset = take_fixed(data, offset, 65)

        wrapped_document_key, offset = unpack_str(data, offset)

        signature, offset = take_fixed(data, offset, 384)

        check_end(data, offset)

        return cls(document_id, sender_id, recipient_id, sender_fingerprint,
                   recipient_fingerprint, sequence_number, timestamp,
                   ephemeral_public_key, wrapped_document_key, signature)
