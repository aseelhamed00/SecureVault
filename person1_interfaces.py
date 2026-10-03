

from crypto.hmac_hkdf import hkdf as _hkdf
from crypto.rsa_pss import pss_sign as _pss_sign, pss_verify as _pss_verify


def pss_sign(private_key, message):
    return _pss_sign(private_key, message)


def pss_verify(public_key, message, signature):
    return _pss_verify(public_key, message, signature)


def hkdf(ikm, salt, info, length):
    return _hkdf(ikm, salt, info, length)
