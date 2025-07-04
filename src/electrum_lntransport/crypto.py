"""Duplicated and slightly adjusted crypto functions from spesmilo/electrum/electrum/crypto.py"""
import logging
from hashlib import sha256 as sha256_hash
from hmac import digest as hmac_digest

import electrum_ecc as ecc

from .util import versiontuple, get_bolt8_nonce_bytes
from .constants import MIN_CRYPTOGRAPHY_VERSION, MIN_CRYPTODOME_VERSION


_logger = logging.getLogger("electrum_lntransport")


HAS_CRYPTODOME = False
try:
    import Cryptodome
    if versiontuple(Cryptodome.__version__) < versiontuple(MIN_CRYPTODOME_VERSION):
        _logger.warning(f"found module 'Cryptodome' but it is too old: {Cryptodome.__version__}<{MIN_CRYPTODOME_VERSION}")
        raise Exception()
    from Cryptodome.Cipher import ChaCha20_Poly1305 as CD_ChaCha20_Poly1305
    from Cryptodome.Cipher import ChaCha20 as CD_ChaCha20
except Exception:
    pass
else:
    HAS_CRYPTODOME = True

HAS_CRYPTOGRAPHY = False
try:
    import cryptography
    if versiontuple(cryptography.__version__) < versiontuple(MIN_CRYPTOGRAPHY_VERSION):
        _logger.warning(f"found module 'cryptography' but it is too old: {cryptography.__version__}<{MIN_CRYPTOGRAPHY_VERSION}")
        raise Exception()
    from cryptography import exceptions
    from cryptography.hazmat.primitives.ciphers import Cipher as CG_Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as CG_algorithms
    from cryptography.hazmat.primitives.ciphers import modes as CG_modes
    from cryptography.hazmat.backends import default_backend as CG_default_backend
    import cryptography.hazmat.primitives.ciphers.aead as CG_aead
except Exception:
    pass
else:
    HAS_CRYPTOGRAPHY = True


def sha256(x: bytes) -> bytes:
    return bytes(sha256_hash(x).digest())


def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    return hmac_digest(key, msg, digest)


def chacha20_poly1305_encrypt(
        *,
        key: bytes,
        nonce: bytes,
        associated_data: bytes = None,
        data: bytes
) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(associated_data, (bytes, bytearray, type(None)))
    assert isinstance(data, (bytes, bytearray))
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) == 12, f"unexpected nonce size: {len(nonce)} (expected: 12)"
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if associated_data is not None:
            cipher.update(associated_data)
        ciphertext, mac = cipher.encrypt_and_digest(plaintext=data)
        return ciphertext + mac
    if HAS_CRYPTOGRAPHY:
        a = CG_aead.ChaCha20Poly1305(key)
        return a.encrypt(nonce, data, associated_data)
    raise Exception("no chacha20 backend found")


def chacha20_poly1305_decrypt(
        *,
        key: bytes,
        nonce: bytes,
        associated_data: bytes = None,
        data: bytes
) -> bytes:
    assert isinstance(key, (bytes, bytearray))
    assert isinstance(nonce, (bytes, bytearray))
    assert isinstance(associated_data, (bytes, bytearray, type(None)))
    assert isinstance(data, (bytes, bytearray))
    assert len(key) == 32, f"unexpected key size: {len(key)} (expected: 32)"
    assert len(nonce) == 12, f"unexpected nonce size: {len(nonce)} (expected: 12)"
    if HAS_CRYPTODOME:
        cipher = CD_ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if associated_data is not None:
            cipher.update(associated_data)
        # raises ValueError if not valid (e.g. incorrect MAC)
        return cipher.decrypt_and_verify(ciphertext=data[:-16], received_mac_tag=data[-16:])
    if HAS_CRYPTOGRAPHY:
        a = CG_aead.ChaCha20Poly1305(key)
        try:
            return a.decrypt(nonce, data, associated_data)
        except cryptography.exceptions.InvalidTag as e:
            raise ValueError("invalid tag") from e
    raise Exception("no chacha20 backend found")


def get_ecdh(priv: bytes, pub: bytes) -> bytes:
    pt = ecc.ECPubkey(pub) * ecc.string_to_number(priv)
    return sha256(pt.get_public_key_bytes())


def privkey_to_pubkey(priv: bytes) -> bytes:
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()


def create_ephemeral_key() -> (bytes, bytes):
    privkey = ecc.ECPrivkey.generate_random_key()
    return privkey.get_secret_bytes(), privkey.get_public_key_bytes()


def aead_encrypt(key: bytes, nonce: int, associated_data: bytes, data: bytes) -> bytes:
    nonce_bytes = get_bolt8_nonce_bytes(nonce)
    return chacha20_poly1305_encrypt(
        key=key,
        nonce=nonce_bytes,
        associated_data=associated_data,
        data=data,
    )


def aead_decrypt(key: bytes, nonce: int, associated_data: bytes, data: bytes) -> bytes:
    nonce_bytes = get_bolt8_nonce_bytes(nonce)
    return chacha20_poly1305_decrypt(
        key=key,
        nonce=nonce_bytes,
        associated_data=associated_data,
        data=data,
    )
