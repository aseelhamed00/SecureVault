import json
import secrets
import time
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw

from crypto.formats import Credential, PublicKey, WrappedPrivateKey
from crypto.hmac_hkdf import compare_tags, hkdf, hmac_sha256
from crypto.p256 import p256_keygen, p256_validate_public
from crypto.rsa_pss import i2osp, rsa_keygen
from crypto.sha256 import sha256
from private_keys import encode_user_id, unwrap_private_keys, wrap_private_keys

AUTH_LABEL = b"securevault:v1:auth"
WRAP_LABEL = b"securevault:v1:wrap"
CONFIG_PATH = Path(__file__).resolve().parent / "benchmarks" / "password_config.json"

ARGON2_PARAM_ORDER = ("memory_cost", "time_cost", "parallelism", "hash_len", "version")
ARGON2_PARAM_LEN = 4 * len(ARGON2_PARAM_ORDER)

CREDENTIAL = "credential"
PUBLIC_KEY = "public_key"
WRAPPED_PRIVATE_KEY = "wrapped_private_key"

RSA_MODULUS_LEN = 384
RSA_EXPONENT_LEN = 3
RSA_BITS = 3072

LOGIN_LABEL = b"securevault:v1:login-response"
DUMMY_SALT_LABEL = b"securevault:v1:dummy-salt"
DUMMY_KEY_LABEL = b"securevault:v1:dummy-key"

LOGIN_CHALLENGE_ID_LEN = 16
LOGIN_CHALLENGE_LEN = 32
LOGIN_RESPONSE_LEN = 32
LOGIN_CHALLENGE_TTL = 30
LOGIN_FAILURE = "Authentication failed"

SESSION_LABEL = b"securevault:v1:session-key"
SESSION_REQUEST_LABEL = b"securevault:v1:session-request"
SESSION_ID_LEN = 16
SESSION_REQUEST_ID_LEN = 16
SESSION_TAG_LEN = 32
SESSION_TTL = 15 * 60

PASSWORD_CHANGE_CONTEXT_OPERATION = b"password-change-context"
PASSWORD_CHANGE_OPERATION = b"change-password"
LOGOUT_OPERATION = b"logout"
PASSWORD_CHANGE_PROOF_LABEL = b"securevault:v1:password-change-proof"
PASSWORD_CHANGE_PROOF_LEN = 32


def validate_password_parameters(params):
    fields = {"memory_cost", "time_cost", "parallelism", "hash_len", "version"}
    if not isinstance(params, dict) or set(params) != fields:
        raise ValueError("Invalid Argon2 parameter fields")
    if any(type(value) is not int for value in params.values()):
        raise ValueError("Argon2 parameters must be integers")
    if not 1 <= params["parallelism"] <= 8:
        raise ValueError("parallelism must be between 1 and 8")
    if not 8192 <= params["memory_cost"] <= 262144:
        raise ValueError("memory_cost must be between 8192 and 262144 KiB")
    if not 1 <= params["time_cost"] <= 10:
        raise ValueError("time_cost must be between 1 and 10")
    if params["hash_len"] != 32 or params["version"] != 19:
        raise ValueError("Expected a 32-byte Argon2id output and version 19")
    return dict(params)


def load_password_parameters():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError("Run python -m benchmarks.passwords first")
    return validate_password_parameters(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))


def derive_password_values(password, salt=None, params=None):
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if salt is None:
        salt = secrets.token_bytes(16)
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("salt must contain exactly 16 bytes")
    if params is None:
        params = load_password_parameters()
    params = validate_password_parameters(params)

    material = hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt, type=Type.ID, **params
    )
    auth_value = hkdf(material, b"", AUTH_LABEL, 32)
    wrap_key = hkdf(material, b"", WRAP_LABEL, 32)
    return {
        "salt": salt,
        "argon2_params": params,
        "auth_value": auth_value,
        "wrap_key": wrap_key,
    }


def encode_argon2_params(params):
    params = validate_password_parameters(params)
    return b"".join(params[name].to_bytes(4, "big") for name in ARGON2_PARAM_ORDER)


def decode_argon2_params(data):
    if not isinstance(data, bytes) or len(data) != ARGON2_PARAM_LEN:
        raise ValueError("Malformed object")

    params = {}
    for index, name in enumerate(ARGON2_PARAM_ORDER):
        params[name] = int.from_bytes(data[index * 4:index * 4 + 4], "big")

    try:
        return validate_password_parameters(params)
    except ValueError:
        raise ValueError("Malformed object") from None


def credential_verifier(auth_value):
    
    if not isinstance(auth_value, bytes) or len(auth_value) != 32:
        raise ValueError("auth_value must contain exactly 32 bytes")
    return sha256(auth_value)


def public_key_fingerprint(record):
    
    if isinstance(record, PublicKey):
        record = record.to_bytes()
    return sha256(record)


def register(user_id, password, params=None):
    
    user_id = encode_user_id(user_id)
    derived = derive_password_values(password, params=params)

    rsa_private, rsa_public = rsa_keygen()
    p256_private, p256_public = p256_keygen()

    bundle = {
        "rsa_private": rsa_private,
        "rsa_public": rsa_public,
        "p256_private": p256_private,
        "p256_public": p256_public,
    }

    wrapped = wrap_private_keys(user_id, derived["wrap_key"], bundle)

    public_key = PublicKey(
        user_id,
        p256_public,
        i2osp(rsa_public["n"], RSA_MODULUS_LEN),
        i2osp(rsa_public["e"], RSA_EXPONENT_LEN),
    )

    credential = Credential(
        user_id,
        derived["salt"],
        encode_argon2_params(derived["argon2_params"]),
        credential_verifier(derived["auth_value"]),
    )

    return {
        "user_id": user_id,
        "records": {
            CREDENTIAL: credential.to_bytes(),
            PUBLIC_KEY: public_key.to_bytes(),
            WRAPPED_PRIVATE_KEY: wrapped.to_bytes(),
        },
        "bundle": bundle,
        "wrap_key": derived["wrap_key"],
        "auth_value": derived["auth_value"],
        "fingerprint": public_key_fingerprint(public_key),
    }


def check_registration_records(records):
    if not isinstance(records, dict) or set(records) != {
        CREDENTIAL,
        PUBLIC_KEY,
        WRAPPED_PRIVATE_KEY,
    }:
        raise ValueError("Malformed object")

    credential = Credential.from_bytes(records[CREDENTIAL])
    public_key = PublicKey.from_bytes(records[PUBLIC_KEY])
    wrapped = WrappedPrivateKey.from_bytes(records[WRAPPED_PRIVATE_KEY])

    user_id = credential.user_id
    if len(user_id) == 0:
        raise ValueError("Malformed object")
    if public_key.user_id != user_id or wrapped.user_id != user_id:
        raise ValueError("Key mismatch")

    decode_argon2_params(credential.argon2_params)

    modulus = int.from_bytes(public_key.rsa_modulus, "big")
    if modulus.bit_length() != RSA_BITS:
        raise ValueError("Malformed object")

    if int.from_bytes(public_key.rsa_public_exponent, "big") != 65537:
        raise ValueError("Malformed object")
    if not p256_validate_public(public_key.p256_public_key):
        raise ValueError("Malformed object")
    if not wrapped.ciphertext:
        raise ValueError("Malformed object")

    return user_id


def account_exists(store, user_id):
    return store.get_account(encode_user_id(user_id)) is not None


def handle_registration(store, records):
    
    user_id = check_registration_records(records)
    store.create_account(user_id, dict(records))
    return user_id


def register_account(store, user_id, password, params=None):
    
    account = register(user_id, password, params)
    handle_registration(store, account["records"])
    return account


def _login_failure():
    raise ValueError(LOGIN_FAILURE)


def _now_seconds(now=None):
    if now is None:
        return int(time.time())
    if not isinstance(now, (int, float)) or isinstance(now, bool):
        raise ValueError("Invalid time")
    return int(now)


def _length_prefixed(data):
    if not isinstance(data, bytes):
        raise ValueError("Malformed object")
    return len(data).to_bytes(4, "big") + data


def _login_transcript(challenge):
    fields = {
        "user_id",
        "challenge_id",
        "challenge",
        "salt",
        "argon2_params",
        "expires_at",
    }
    if not isinstance(challenge, dict) or set(challenge) != fields:
        raise ValueError("Malformed object")

    user_id = challenge["user_id"]
    challenge_id = challenge["challenge_id"]
    nonce = challenge["challenge"]
    salt = challenge["salt"]
    argon2_params = challenge["argon2_params"]
    expires_at = challenge["expires_at"]

    if not isinstance(user_id, bytes) or not user_id:
        raise ValueError("Malformed object")
    if not isinstance(challenge_id, bytes) or len(challenge_id) != LOGIN_CHALLENGE_ID_LEN:
        raise ValueError("Malformed object")
    if not isinstance(nonce, bytes) or len(nonce) != LOGIN_CHALLENGE_LEN:
        raise ValueError("Malformed object")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("Malformed object")
    if not isinstance(argon2_params, bytes) or len(argon2_params) != ARGON2_PARAM_LEN:
        raise ValueError("Malformed object")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("Malformed object")
    if expires_at < 0 or expires_at >= (1 << 64):
        raise ValueError("Malformed object")

    return (
        LOGIN_LABEL
        + _length_prefixed(user_id)
        + challenge_id
        + nonce
        + salt
        + argon2_params
        + expires_at.to_bytes(8, "big")
    )


def begin_login(store, user_id, now=None):
    
    user_id = encode_user_id(user_id)
    now = _now_seconds(now)

    server_secret = store.get_or_create_server_secret()
    dummy_salt = hmac_sha256(
        server_secret, DUMMY_SALT_LABEL + _length_prefixed(user_id)
    )[:16]
    dummy_params = encode_argon2_params(load_password_parameters())

    credential = None
    records = store.get_account(user_id)
    if records is not None:
        try:
            candidate = Credential.from_bytes(records[CREDENTIAL])
            if candidate.user_id == user_id:
                decode_argon2_params(candidate.argon2_params)
                credential = candidate
        except ValueError:
            credential = None

    is_real = credential is not None
    salt = credential.salt if is_real else dummy_salt
    argon2_params = credential.argon2_params if is_real else dummy_params

    challenge = {
        "user_id": user_id,
        "challenge_id": secrets.token_bytes(LOGIN_CHALLENGE_ID_LEN),
        "challenge": secrets.token_bytes(LOGIN_CHALLENGE_LEN),
        "salt": salt,
        "argon2_params": argon2_params,
        "expires_at": now + LOGIN_CHALLENGE_TTL,
    }

    store.save_login_challenge(
        challenge["challenge_id"],
        user_id,
        challenge["challenge"],
        salt,
        argon2_params,
        challenge["expires_at"],
        is_real,
    )
    return challenge


def make_login_response_with_state(password, challenge):
    
    try:
        transcript = _login_transcript(challenge)
        params = decode_argon2_params(challenge["argon2_params"])
        derived = derive_password_values(
            password,
            salt=challenge["salt"],
            params=params,
        )
    except (TypeError, ValueError):
        _login_failure()

    login_key = credential_verifier(derived["auth_value"])
    response = {
        "challenge_id": challenge["challenge_id"],
        "response": hmac_sha256(login_key, transcript),
    }
    local_state = {
        "wrap_key": derived["wrap_key"],
        "login_key": login_key,
    }
    return response, local_state


def make_login_response(password, challenge):
    
    response, local_state = make_login_response_with_state(password, challenge)
    return response, local_state["wrap_key"]


def finish_login(store, response, now=None):
    
    now = _now_seconds(now)

    if not isinstance(response, dict) or set(response) != {"challenge_id", "response"}:
        _login_failure()

    challenge_id = response["challenge_id"]
    received = response["response"]

    if (
        not isinstance(challenge_id, bytes)
        or len(challenge_id) != LOGIN_CHALLENGE_ID_LEN
        or not isinstance(received, bytes)
        or len(received) != LOGIN_RESPONSE_LEN
    ):
        _login_failure()

    state = store.consume_login_challenge(challenge_id)
    if state is None:
        _login_failure()

    public_challenge = {
        "user_id": state["user_id"],
        "challenge_id": state["challenge_id"],
        "challenge": state["challenge"],
        "salt": state["salt"],
        "argon2_params": state["argon2_params"],
        "expires_at": state["expires_at"],
    }

    try:
        transcript = _login_transcript(public_challenge)
        server_secret = store.get_or_create_server_secret()
        dummy_key = hmac_sha256(
            server_secret,
            DUMMY_KEY_LABEL + _length_prefixed(state["user_id"]),
        )

        records = store.get_account(state["user_id"])
        credential = None
        if records is not None:
            candidate = Credential.from_bytes(records[CREDENTIAL])
            if (
                candidate.user_id == state["user_id"]
                and candidate.salt == state["salt"]
                and candidate.argon2_params == state["argon2_params"]
            ):
                decode_argon2_params(candidate.argon2_params)
                credential = candidate

        is_real = state["is_real"] and credential is not None
        expected_key = credential.auth_value if is_real else dummy_key
        expected = hmac_sha256(expected_key, transcript)

        valid_response = compare_tags(received, expected)
        expired = now > state["expires_at"]

        if not is_real or expired or not valid_response:
            _login_failure()

        session = create_session(
            store,
            state["user_id"],
            expected_key,
            now=now,
        )

        return {
            "user_id": state["user_id"],
            PUBLIC_KEY: records[PUBLIC_KEY],
            WRAPPED_PRIVATE_KEY: records[WRAPPED_PRIVATE_KEY],
            "session": session,
        }
    except ValueError as error:
        if str(error) == LOGIN_FAILURE:
            raise
        _login_failure()


def _check_login_public_key(user_id, public_record, bundle):
    try:
        public_key = PublicKey.from_bytes(public_record)
    except ValueError:
        _login_failure()

    if public_key.user_id != user_id:
        _login_failure()

    if public_key.p256_public_key != bundle["p256_public"]:
        _login_failure()

    if int.from_bytes(public_key.rsa_modulus, "big") != bundle["rsa_public"]["n"]:
        _login_failure()

    if int.from_bytes(public_key.rsa_public_exponent, "big") != bundle["rsa_public"]["e"]:
        _login_failure()

    return public_key


def _derive_session_key(login_key, session_id):
    if not isinstance(login_key, bytes) or len(login_key) != 32:
        _login_failure()
    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_LEN:
        _login_failure()
    return hkdf(login_key, session_id, SESSION_LABEL, 32)


def create_session(store, user_id, login_key, now=None):
    
    user_id = encode_user_id(user_id)
    now = _now_seconds(now)

    if not isinstance(login_key, bytes) or len(login_key) != 32:
        _login_failure()

    records = store.get_account(user_id)
    if records is None:
        _login_failure()

    try:
        credential = Credential.from_bytes(records[CREDENTIAL])
    except ValueError:
        _login_failure()

    if credential.user_id != user_id or not compare_tags(credential.auth_value, login_key):
        _login_failure()

    session_id = secrets.token_bytes(SESSION_ID_LEN)
    expires_at = now + SESSION_TTL
    store.save_session(session_id, user_id, expires_at)

    return {
        "session_id": session_id,
        "user_id": user_id,
        "expires_at": expires_at,
    }


def _validated_session_state(store, session_id, now=None):
    now = _now_seconds(now)
    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_LEN:
        _login_failure()

    state = store.get_session(session_id)
    if state is None or state["invalidated"] or now >= state["expires_at"]:
        _login_failure()

    records = store.get_account(state["user_id"])
    if records is None:
        _login_failure()

    try:
        credential = Credential.from_bytes(records[CREDENTIAL])
    except ValueError:
        _login_failure()

    if credential.user_id != state["user_id"]:
        _login_failure()

    state = dict(state)
    state["session_key"] = _derive_session_key(credential.auth_value, session_id)
    return state


def validate_session(store, session_id, now=None):
   
    state = _validated_session_state(store, session_id, now=now)
    return {
        "session_id": state["session_id"],
        "user_id": state["user_id"],
        "expires_at": state["expires_at"],
    }


def invalidate_session(store, session_id):
    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_LEN:
        _login_failure()
    if not store.invalidate_session(session_id):
        _login_failure()
    return True


def _session_request_transcript(request):
    fields = {"session_id", "request_id", "user_id", "operation", "payload"}
    if not isinstance(request, dict) or set(request) != fields:
        raise ValueError("Malformed object")

    session_id = request["session_id"]
    request_id = request["request_id"]
    user_id = request["user_id"]
    operation = request["operation"]
    payload = request["payload"]

    if not isinstance(session_id, bytes) or len(session_id) != SESSION_ID_LEN:
        raise ValueError("Malformed object")
    if not isinstance(request_id, bytes) or len(request_id) != SESSION_REQUEST_ID_LEN:
        raise ValueError("Malformed object")
    if not isinstance(user_id, bytes) or not user_id:
        raise ValueError("Malformed object")
    if not isinstance(operation, bytes) or not operation:
        raise ValueError("Malformed object")
    if not isinstance(payload, bytes):
        raise ValueError("Malformed object")

    return (
        SESSION_REQUEST_LABEL
        + session_id
        + request_id
        + _length_prefixed(user_id)
        + _length_prefixed(operation)
        + _length_prefixed(payload)
    )


def make_session_request(session, operation, payload=b"", user_id=None, request_id=None):
    
    required = {"session_id", "user_id", "expires_at", "session_key"}
    if not isinstance(session, dict) or set(session) != required:
        _login_failure()

    session_id = session["session_id"]
    session_key = session["session_key"]

    if user_id is None:
        user_id = session["user_id"]
    else:
        user_id = encode_user_id(user_id)

    if isinstance(operation, str):
        operation = operation.encode("utf-8")
    if not isinstance(operation, bytes) or not operation:
        raise ValueError("operation must be a non-empty string or byte string")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")

    if request_id is None:
        request_id = secrets.token_bytes(SESSION_REQUEST_ID_LEN)

    unsigned = {
        "session_id": session_id,
        "request_id": request_id,
        "user_id": user_id,
        "operation": operation,
        "payload": payload,
    }

    try:
        transcript = _session_request_transcript(unsigned)
    except ValueError:
        _login_failure()

    if not isinstance(session_key, bytes) or len(session_key) != 32:
        _login_failure()

    request = dict(unsigned)
    request["tag"] = hmac_sha256(session_key, transcript)
    return request


def validate_session_request(store, request, now=None):
    
    now = _now_seconds(now)
    if not isinstance(request, dict) or set(request) != {
        "session_id", "request_id", "user_id", "operation", "payload", "tag"
    }:
        _login_failure()

    tag = request["tag"]
    if not isinstance(tag, bytes) or len(tag) != SESSION_TAG_LEN:
        _login_failure()

    unsigned = {key: request[key] for key in (
        "session_id", "request_id", "user_id", "operation", "payload"
    )}

    try:
        transcript = _session_request_transcript(unsigned)
        state = _validated_session_state(store, request["session_id"], now=now)
    except (TypeError, ValueError):
        _login_failure()

    expected = hmac_sha256(state["session_key"], transcript)
    valid_tag = compare_tags(tag, expected)
    correct_identity = request["user_id"] == state["user_id"]

    if not valid_tag or not correct_identity:
        _login_failure()

    if not store.claim_session_request(
        request["session_id"], request["request_id"], now
    ):
        _login_failure()

    return {
        "session_id": state["session_id"],
        "request_id": request["request_id"],
        "user_id": state["user_id"],
        "operation": request["operation"],
        "payload": request["payload"],
    }


def handle_logout(store, request, now=None):
    try:
        accepted = validate_session_request(store, request, now=now)
        if accepted["operation"] != LOGOUT_OPERATION:
            _login_failure()
        invalidate_session(store, accepted["session_id"])
    except (TypeError, ValueError):
        _login_failure()

    return {
        "user_id": accepted["user_id"],
        "logged_out": True,
    }


def login(store, user_id, password, now=None):
    
    try:
        challenge = begin_login(store, user_id, now=now)
        response, local_state = make_login_response_with_state(password, challenge)
        accepted = finish_login(store, response, now=now)

        wrap_key = local_state["wrap_key"]
        bundle = unwrap_private_keys(
            accepted["user_id"],
            wrap_key,
            accepted[WRAPPED_PRIVATE_KEY],
        )
        public_key = _check_login_public_key(
            accepted["user_id"],
            accepted[PUBLIC_KEY],
            bundle,
        )

        session_public = accepted["session"]
        session = {
            "session_id": session_public["session_id"],
            "user_id": accepted["user_id"],
            "expires_at": session_public["expires_at"],
            "session_key": _derive_session_key(
                local_state["login_key"],
                session_public["session_id"],
            ),
        }
    except (TypeError, ValueError):
        _login_failure()

    return {
        "user_id": accepted["user_id"],
        "bundle": bundle,
        "wrap_key": wrap_key,
        "public_key": public_key,
        "fingerprint": public_key_fingerprint(public_key),
        "session": session,
    }

def _read_length_prefixed(buffer, offset):
    if not isinstance(buffer, bytes) or not isinstance(offset, int):
        raise ValueError("Malformed object")
    if offset < 0 or offset + 4 > len(buffer):
        raise ValueError("Malformed object")
    length = int.from_bytes(buffer[offset:offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(buffer):
        raise ValueError("Malformed object")
    return buffer[start:end], end


def _password_change_body(new_credential, new_wrapped_private_key):
    if not isinstance(new_credential, bytes) or not isinstance(new_wrapped_private_key, bytes):
        raise ValueError("Malformed object")
    return _length_prefixed(new_credential) + _length_prefixed(new_wrapped_private_key)


def _password_change_proof_transcript(
    user_id,
    session_id,
    salt,
    argon2_params,
    public_key_record,
    current_wrapped_private_key,
    change_body,
):
    user_id = encode_user_id(user_id)
    values = (
        session_id,
        salt,
        argon2_params,
        public_key_record,
        current_wrapped_private_key,
        change_body,
    )
    if any(not isinstance(value, bytes) for value in values):
        raise ValueError("Malformed object")
    if len(session_id) != SESSION_ID_LEN or len(salt) != 16:
        raise ValueError("Malformed object")
    if len(argon2_params) != ARGON2_PARAM_LEN:
        raise ValueError("Malformed object")

    return (
        PASSWORD_CHANGE_PROOF_LABEL
        + session_id
        + _length_prefixed(user_id)
        + salt
        + argon2_params
        + sha256(public_key_record)
        + sha256(current_wrapped_private_key)
        + sha256(change_body)
    )


def make_password_change_context(records, user_id):
    
    user_id = encode_user_id(user_id)
    if not isinstance(records, dict) or set(records) != {
        CREDENTIAL, PUBLIC_KEY, WRAPPED_PRIVATE_KEY
    }:
        _login_failure()

    try:
        credential = Credential.from_bytes(records[CREDENTIAL])
        public_key = PublicKey.from_bytes(records[PUBLIC_KEY])
        wrapped = WrappedPrivateKey.from_bytes(records[WRAPPED_PRIVATE_KEY])
        decode_argon2_params(credential.argon2_params)
    except (TypeError, ValueError):
        _login_failure()

    if (
        credential.user_id != user_id
        or public_key.user_id != user_id
        or wrapped.user_id != user_id
    ):
        _login_failure()

    return {
        "user_id": user_id,
        "salt": credential.salt,
        "argon2_params": credential.argon2_params,
        PUBLIC_KEY: records[PUBLIC_KEY],
        WRAPPED_PRIVATE_KEY: records[WRAPPED_PRIVATE_KEY],
    }

def _encode_password_change_payload(new_credential, new_wrapped_private_key, proof):
    if not isinstance(proof, bytes) or len(proof) != PASSWORD_CHANGE_PROOF_LEN:
        raise ValueError("Malformed object")
    return _password_change_body(new_credential, new_wrapped_private_key) + proof


def _decode_password_change_payload(payload):
    if not isinstance(payload, bytes):
        raise ValueError("Malformed object")

    new_credential, offset = _read_length_prefixed(payload, 0)
    new_wrapped, offset = _read_length_prefixed(payload, offset)

    if len(payload) - offset != PASSWORD_CHANGE_PROOF_LEN:
        raise ValueError("Malformed object")

    proof = payload[offset:]
    return new_credential, new_wrapped, proof


def _derive_new_password_values(new_password, old_salt, params=None):
    if params is None:
        params = load_password_parameters()

    # A new password record must never intentionally reuse the old account salt.
    # A random 16-byte collision is already negligible; the loop makes the rule
    # explicit and testable.
    while True:
        derived = derive_password_values(new_password, params=params)
        if derived["salt"] != old_salt:
            return derived


def handle_password_change_context(store, request, now=None):
    
    try:
        accepted = validate_session_request(store, request, now=now)
        if accepted["operation"] != PASSWORD_CHANGE_CONTEXT_OPERATION:
            _login_failure()
        records = store.get_account(accepted["user_id"])
        if records is None:
            _login_failure()
        return make_password_change_context(records, accepted["user_id"])
    except (TypeError, ValueError):
        _login_failure()


def prepare_password_change(
    user_id,
    old_password,
    new_password,
    context,
    session,
    params=None,
):
   
    user_id = encode_user_id(user_id)

    required_session = {"session_id", "user_id", "expires_at", "session_key"}
    if not isinstance(session, dict) or set(session) != required_session:
        _login_failure()
    if session["user_id"] != user_id:
        _login_failure()

    required_context = {
        "user_id", "salt", "argon2_params", PUBLIC_KEY, WRAPPED_PRIVATE_KEY
    }
    if not isinstance(context, dict) or set(context) != required_context:
        _login_failure()
    if context["user_id"] != user_id:
        _login_failure()

    try:
        current_params = decode_argon2_params(context["argon2_params"])
        old_derived = derive_password_values(
            old_password,
            salt=context["salt"],
            params=current_params,
        )
        old_login_key = credential_verifier(old_derived["auth_value"])
        bundle = unwrap_private_keys(
            user_id,
            old_derived["wrap_key"],
            context[WRAPPED_PRIVATE_KEY],
        )
        public_key = _check_login_public_key(
            user_id, context[PUBLIC_KEY], bundle
        )
        new_derived = _derive_new_password_values(
            new_password,
            context["salt"],
            params=params,
        )
        new_wrapped = wrap_private_keys(
            user_id,
            new_derived["wrap_key"],
            bundle,
        )
        new_credential = Credential(
            user_id,
            new_derived["salt"],
            encode_argon2_params(new_derived["argon2_params"]),
            credential_verifier(new_derived["auth_value"]),
        )
    except (TypeError, ValueError):
        _login_failure()

    new_credential_bytes = new_credential.to_bytes()
    new_wrapped_bytes = new_wrapped.to_bytes()
    change_body = _password_change_body(
        new_credential_bytes,
        new_wrapped_bytes,
    )
    proof_transcript = _password_change_proof_transcript(
        user_id,
        session["session_id"],
        context["salt"],
        context["argon2_params"],
        context[PUBLIC_KEY],
        context[WRAPPED_PRIVATE_KEY],
        change_body,
    )
    proof = hmac_sha256(old_login_key, proof_transcript)
    payload = _encode_password_change_payload(
        new_credential_bytes,
        new_wrapped_bytes,
        proof,
    )
    request = make_session_request(
        session,
        PASSWORD_CHANGE_OPERATION,
        payload,
    )

    local_state = {
        "user_id": user_id,
        "bundle": bundle,
        "public_key": public_key,
        "fingerprint": public_key_fingerprint(public_key),
        "wrap_key": new_derived["wrap_key"],
        "credential": new_credential_bytes,
        "wrapped_private_key": new_wrapped_bytes,
    }
    return request, local_state


def handle_password_change(store, request, now=None):
   
    try:
        accepted = validate_session_request(store, request, now=now)
        if accepted["operation"] != PASSWORD_CHANGE_OPERATION:
            _login_failure()

        new_credential_bytes, new_wrapped_bytes, proof = _decode_password_change_payload(
            accepted["payload"]
        )
        user_id = accepted["user_id"]

        current = store.get_account(user_id)
        if current is None:
            _login_failure()

        current_credential = Credential.from_bytes(current[CREDENTIAL])
        new_credential = Credential.from_bytes(new_credential_bytes)
        new_wrapped = WrappedPrivateKey.from_bytes(new_wrapped_bytes)

        if (
            current_credential.user_id != user_id
            or new_credential.user_id != user_id
            or new_wrapped.user_id != user_id
        ):
            _login_failure()

        decode_argon2_params(current_credential.argon2_params)
        decode_argon2_params(new_credential.argon2_params)

        if new_credential.salt == current_credential.salt:
            _login_failure()
        if not new_wrapped.ciphertext:
            _login_failure()

        change_body = _password_change_body(
            new_credential_bytes,
            new_wrapped_bytes,
        )
        proof_transcript = _password_change_proof_transcript(
            user_id,
            accepted["session_id"],
            current_credential.salt,
            current_credential.argon2_params,
            current[PUBLIC_KEY],
            current[WRAPPED_PRIVATE_KEY],
            change_body,
        )
        expected_proof = hmac_sha256(
            current_credential.auth_value,
            proof_transcript,
        )
        if not compare_tags(proof, expected_proof):
            _login_failure()

        store.update_password_records(
            user_id,
            current[CREDENTIAL],
            current[WRAPPED_PRIVATE_KEY],
            new_credential_bytes,
            new_wrapped_bytes,
        )
    except (TypeError, ValueError):
        _login_failure()

    return {
        "user_id": user_id,
        "password_changed": True,
    }


def change_password(
    store,
    session,
    old_password,
    new_password,
    params=None,
    now=None,
):
    
    try:
        if not isinstance(session, dict) or "session_id" not in session:
            _login_failure()
        state = validate_session(store, session["session_id"], now=now)
        user_id = state["user_id"]
        records = store.get_account(user_id)
        if records is None:
            _login_failure()
        context = make_password_change_context(records, user_id)

        request, local_state = prepare_password_change(
            user_id,
            old_password,
            new_password,
            context,
            session,
            params=params,
        )
        accepted = handle_password_change(store, request, now=now)
    except (TypeError, ValueError):
        _login_failure()

    return {
        "user_id": accepted["user_id"],
        "bundle": local_state["bundle"],
        "wrap_key": local_state["wrap_key"],
        "public_key": local_state["public_key"],
        "fingerprint": local_state["fingerprint"],
        "session_invalidated": True,
    }

