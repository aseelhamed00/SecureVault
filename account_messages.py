import json

VERSION = 1


TYPE_REGISTER_REQUEST = 16
TYPE_LOGIN_BEGIN_REQUEST = 17
TYPE_LOGIN_CHALLENGE = 18
TYPE_LOGIN_FINISH_REQUEST = 19
TYPE_LOGIN_RESULT = 20
TYPE_SESSION_REQUEST = 21
TYPE_SESSION_RESULT = 22
TYPE_ERROR = 23

_KNOWN_TYPES = {
    TYPE_REGISTER_REQUEST,
    TYPE_LOGIN_BEGIN_REQUEST,
    TYPE_LOGIN_CHALLENGE,
    TYPE_LOGIN_FINISH_REQUEST,
    TYPE_LOGIN_RESULT,
    TYPE_SESSION_REQUEST,
    TYPE_SESSION_RESULT,
    TYPE_ERROR,
}

_BYTES_MARKER = "$bytes"


def _encode_value(value):
    if isinstance(value, bytes):
        return {_BYTES_MARKER: value.hex()}
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("Message dictionary keys must be strings")
        return {key: _encode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise ValueError("Unsupported message value")


def _decode_value(value):
    if isinstance(value, dict):
        if set(value) == {_BYTES_MARKER}:
            encoded = value[_BYTES_MARKER]
            if not isinstance(encoded, str):
                raise ValueError("Malformed message")
            try:
                return bytes.fromhex(encoded)
            except ValueError:
                raise ValueError("Malformed message") from None
        if _BYTES_MARKER in value:
            raise ValueError("Malformed message")
        return {key: _decode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise ValueError("Malformed message")


def peek_type_byte(payload: bytes) -> int:
    if not isinstance(payload, bytes) or len(payload) < 2:
        raise ValueError("Malformed message")
    if payload[0] != VERSION:
        raise ValueError("Malformed message")
    return payload[1]


def encode_dict_message(type_byte: int, body: dict, reply_to: str = "") -> bytes:
    if type(type_byte) is not int or type_byte not in _KNOWN_TYPES:
        raise ValueError("Invalid message type")
    if not isinstance(body, dict):
        raise ValueError("Message body must be a dictionary")
    if not isinstance(reply_to, str):
        raise ValueError("reply_to must be a string")

    reply_bytes = reply_to.encode("utf-8")
    if len(reply_bytes) > 0xFFFFFFFF:
        raise ValueError("reply_to is too long")

    encoded_body = json.dumps(
        _encode_value(body),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    return (
        bytes([VERSION, type_byte])
        + len(reply_bytes).to_bytes(4, "big")
        + reply_bytes
        + encoded_body
    )


def decode_dict_message(expected_type: int, payload: bytes):
    if type(expected_type) is not int or expected_type not in _KNOWN_TYPES:
        raise ValueError("Invalid message type")
    if not isinstance(payload, bytes) or len(payload) < 6:
        raise ValueError("Malformed message")
    if payload[0] != VERSION or payload[1] != expected_type:
        raise ValueError("Malformed message")

    reply_len = int.from_bytes(payload[2:6], "big")
    reply_end = 6 + reply_len
    if reply_end > len(payload):
        raise ValueError("Malformed message")

    try:
        reply_to = payload[6:reply_end].decode("utf-8")
        raw_body = json.loads(payload[reply_end:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Malformed message") from None

    if not isinstance(raw_body, dict):
        raise ValueError("Malformed message")

    body = _decode_value(raw_body)
    if not isinstance(body, dict):
        raise ValueError("Malformed message")
    return reply_to, body
