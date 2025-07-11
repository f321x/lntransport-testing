# Copyright (C) 2018 Adam Gibson (waxwing)
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

# Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8

import hashlib
import asyncio
from asyncio import Queue

from functools import cached_property, partial
from typing import Optional, Tuple

from aiorpcx.session import SessionKind, SessionBase
from aiorpcx.framing import FramerBase
from aiorpcx.rawsocket import RSTransport

import electrum_ecc as ecc

from .crypto import (sha256, hmac_oneshot, get_ecdh, privkey_to_pubkey, create_ephemeral_key,
                     aead_encrypt, aead_decrypt)
from .util import log_exceptions, LNPeerAddr, ESocksProxy
from .constants import MSG_SIZE_LEN, NOISE_PROTOCOL_NAME, BOLT8_HANDSHAKE_VERSION


class QueueFramer(FramerBase):

    def __init__(self):
        self.queue = Queue()

    def frame(self, message):
        raise NotImplementedError

    def received_message(self, msg):
        self.queue.put_nowait(msg)

    async def receive_message(self):
        msg = await self.queue.get()
        return msg

    def fail(self, exception):
        self.exception = exception


class LNSession(SessionBase):
    pass


class LightningPeerConnectionClosed(Exception): pass
class HandshakeFailed(Exception): pass


class HandshakeState:
    protocol_name: bytes = NOISE_PROTOCOL_NAME
    handshake_version: bytes = BOLT8_HANDSHAKE_VERSION

    def __init__(self, prologue: bytes, responder_pub: bytes):
        self.prologue = prologue
        self.responder_pub = responder_pub
        self.h = sha256(self.protocol_name)  # type: bytes
        self.ck = self.h  # type: bytes
        self.update(self.prologue)
        self.update(self.responder_pub)

    def update(self, data: bytes) -> bytes:
        self.h = sha256(self.h + data)
        return self.h


def get_bolt8_hkdf(salt: bytes, ikm: bytes) -> Tuple[bytes, bytes]:
    """RFC5869 HKDF instantiated in the specific form
    used in Lightning BOLT 8:
    Extract and expand to 64 bytes using HMAC-SHA256,
    with info field set to a zero length string as per BOLT8
    Return as two 32 byte fields.
    """
    #Extract
    prk: bytes = hmac_oneshot(salt, msg=ikm, digest=hashlib.sha256)
    assert len(prk) == 32
    #Expand
    info = b""
    T0 = b""
    T1 = hmac_oneshot(prk, T0 + info + b"\x01", digest=hashlib.sha256)
    T2 = hmac_oneshot(prk, T1 + info + b"\x02", digest=hashlib.sha256)
    assert len(T1 + T2) == 64
    return T1, T2


def act1_initiator_message(hs: HandshakeState, epriv: bytes, epub: bytes) -> Tuple[bytes, bytes]:
    ss = get_ecdh(epriv, hs.responder_pub)
    ck2, temp_k1 = get_bolt8_hkdf(hs.ck, ss)
    hs.ck = ck2
    c = aead_encrypt(temp_k1, 0, hs.update(epub), b"")
    #for next step if we do it
    hs.update(c)
    msg = hs.handshake_version + epub + c
    assert len(msg) == 50
    return msg, temp_k1


class LNTransport(RSTransport):
    _privkey: bytes
    _remote_pubkey: bytes

    def __init__(
        self,
        prologue: bytes,
        session_factory,
        privkey: bytes,
        peer_addr: Optional[LNPeerAddr] = None,
        whitelist=None
    ):
        framer = QueueFramer()
        kind = SessionKind.SERVER if peer_addr is None else SessionKind.CLIENT
        self.peer_addr = peer_addr # todo: remove this, pass only pubkey
        self._remote_pubkey = peer_addr.pubkey if peer_addr else None
        self.prologue = prologue
        self.msg_size_len = MSG_SIZE_LEN[prologue]
        self.whitelist = whitelist

        RSTransport.__init__(self, session_factory, framer, kind)
        assert type(privkey) is bytes and len(privkey) == 32
        self._privkey = privkey
        self._data = bytearray()
        self._data_received = asyncio.Event()
        self.handshake_done = asyncio.Event()
        self._decrypt_messages_task = None  # type: Optional[asyncio.Task]

    def is_listener(self) -> bool:
        return self.kind == SessionKind.SERVER

    @log_exceptions
    async def read_data(self, length: int) -> bytes:
        await self._data_received.wait()
        chunk = self._data[:length]
        del self._data[:length]
        if not self._data:
            self._data_received.clear()
        return chunk

    async def write(self, message: bytes) -> None:
        self.send_bytes(message)

    def send_bytes(self, msg: bytes) -> None:
        l = len(msg).to_bytes(self.msg_size_len, 'big')
        lc = aead_encrypt(self.sk, self.sn(), b'', l)
        c = aead_encrypt(self.sk, self.sn(), b'', msg)
        assert len(lc) == 16 + self.msg_size_len
        assert len(c) == len(msg) + 16
        self._asyncio_transport.write(lc+c)

    @log_exceptions
    async def decrypt_messages(self):
        if self.is_listener():
            await self.listener_handshake()
        else:
            await self.handshake()
        header_length = 16 + self.msg_size_len
        while True:
            rn_l, rk_l = self.rn()
            rn_m, rk_m = self.rn()
            while True:
                if len(self._data) >= header_length:
                    lc = bytes(self._data[:header_length])
                    l = aead_decrypt(rk_l, rn_l, b'', lc)
                    length = int.from_bytes(l, 'big')
                    offset = header_length + length + 16
                    if len(self._data) >= offset:
                        c = bytes(self._data[header_length:offset])
                        del self._data[:offset]  # much faster than: buffer=buffer[offset:]
                        msg = aead_decrypt(rk_m, rn_m, b'', c)
                        self._framer.received_message(msg)
                        break
                await self._data_received.wait()
                self._data_received.clear()

    async def read_messages(self):
        while True:
            msg = await self.receive_message()
            yield msg

    def rn(self):
        o = self._rn, self.rk
        self._rn += 1
        if self._rn == 1000:
            self.r_ck, self.rk = get_bolt8_hkdf(self.r_ck, self.rk)
            self._rn = 0
        return o

    def sn(self):
        o = self._sn
        self._sn += 1
        if self._sn == 1000:
            self.s_ck, self.sk = get_bolt8_hkdf(self.s_ck, self.sk)
            self._sn = 0
        return o

    def init_counters(self, ck):
        self._sn = 0
        self._rn = 0
        self.r_ck = ck
        self.s_ck = ck

    async def listener_handshake(self, *, epriv: bytes = None):
        hs = HandshakeState(self.prologue, privkey_to_pubkey(self._privkey))
        act1 = b''
        while len(act1) < 50:
            buf = await self.read_data(50 - len(act1))
            if not buf:
                raise HandshakeFailed('responder disconnected')
            act1 += buf
        if len(act1) != 50:
            raise HandshakeFailed('responder: short act 1 read, length is ' + str(len(act1)))
        if bytes([act1[0]]) != HandshakeState.handshake_version:
            raise HandshakeFailed('responder: bad handshake version in act 1')
        c = act1[-16:]
        re = act1[1:34]
        h = hs.update(re)
        ss = get_ecdh(self._privkey, re)
        ck, temp_k1 = get_bolt8_hkdf(sha256(HandshakeState.protocol_name), ss)
        _p = aead_decrypt(temp_k1, 0, h, c)
        hs.update(c)
        # act 2
        if epriv is None:
            epriv, epub = create_ephemeral_key()
        else:
            epub = ecc.ECPrivkey(epriv).get_public_key_bytes()
        hs.ck = ck
        hs.responder_pub = re
        msg, temp_k2 = act1_initiator_message(hs, epriv, epub)
        self._asyncio_transport.write(msg)
        # act 3
        act3 = b''
        while len(act3) < 66:
            buf = await self.read_data(66 - len(act3))
            if not buf:
                raise HandshakeFailed('responder disconnected')
            act3 += buf
        if len(act3) != 66:
            raise HandshakeFailed('responder: short act 3 read, length is ' + str(len(act3)))
        if bytes([act3[0]]) != HandshakeState.handshake_version:
            raise HandshakeFailed('responder: bad handshake version in act 3')
        c = act3[1:50]
        t = act3[-16:]
        rs = aead_decrypt(temp_k2, 1, hs.h, c)
        ss = get_ecdh(epriv, rs)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        _p = aead_decrypt(temp_k3, 0, hs.update(c), t)
        self.rk, self.sk = get_bolt8_hkdf(ck, b'')
        self.init_counters(ck)
        self._remote_pubkey = rs
        if self.whitelist is not None and rs not in self.whitelist:
            raise HandshakeFailed(f'Not authorised {rs.hex()}')
        self.handshake_done.set()
        return rs

    def connection_made(self, transport):
        RSTransport.connection_made(self, transport)
        self._decrypt_messages_task = self.loop.create_task(self.decrypt_messages())

    def connection_lost(self, exc):
        RSTransport.connection_lost(self, exc)
        if self._process_messages_task is not None:
            self._process_messages_task.cancel() # fixme: this should be done in parent class
            self._process_messages_task = None
        if self._decrypt_messages_task is not None:
            self._decrypt_messages_task.cancel()
            self._decrypt_messages_task = None

    def data_received(self, chunk: bytes) -> None:
        self._data += chunk
        self._data_received.set()
        self.session.data_received(chunk)

    async def handshake(self) -> None:
        assert self._remote_pubkey is not None
        hs = HandshakeState(self.prologue, self._remote_pubkey)
        # Get a new ephemeral key
        epriv, epub = create_ephemeral_key()
        msg, _temp_k1 = act1_initiator_message(hs, epriv, epub)
        # act 1
        self._asyncio_transport.write(msg)
        rspns = await self.read_data(2**10)
        if len(rspns) != 50:
            raise HandshakeFailed(
                f"Lightning handshake act 1 response has bad length, "
                f"are you sure this is the right pubkey? {self._remote_pubkey.hex()}"
            )
        hver, alice_epub, tag = rspns[0], rspns[1:34], rspns[34:]
        if bytes([hver]) != hs.handshake_version:
            raise HandshakeFailed("unexpected handshake version: {}".format(hver))
        # act 2
        hs.update(alice_epub)
        ss = get_ecdh(epriv, alice_epub)
        ck, temp_k2 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        p = aead_decrypt(temp_k2, 0, hs.h, tag)
        hs.update(tag)
        # act 3
        my_pubkey = privkey_to_pubkey(self._privkey)
        c = aead_encrypt(temp_k2, 1, hs.h, my_pubkey)
        hs.update(c)
        ss = get_ecdh(self._privkey[:32], alice_epub)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        t = aead_encrypt(temp_k3, 0, hs.h, b'')
        msg = hs.handshake_version + c + t
        self._asyncio_transport.write(msg)
        self.sk, self.rk = get_bolt8_hkdf(hs.ck, b'')
        self.init_counters(ck)
        self.handshake_done.set()

    @cached_property
    def _id_hash(self) -> str:
        id_int = id(self)
        id_bytes = id_int.to_bytes((id_int.bit_length() + 7) // 8, byteorder='big')
        return sha256(id_bytes).hex()

    def name(self) -> str:
        pubkey = self.remote_pubkey()
        if not pubkey:
            return ''
        pubkey_hex = pubkey.hex() if pubkey else pubkey
        return f"{pubkey_hex[:10]}-{self._id_hash[:8]}"

    def remote_pubkey(self) -> Optional[bytes]:
        return self._remote_pubkey


class LNClient:

    def __init__(
        self,
        prologue: bytes,
        privkey: bytes,
        session_factory,
        peer_addr: LNPeerAddr,
        proxy: Optional[ESocksProxy] = None,
        loop: Optional[asyncio.EventLoop] = None,
    ):
        assert type(privkey) is bytes and len(privkey) == 32
        self.privkey = privkey
        self.peer_addr = peer_addr
        self.proxy = proxy
        self.loop = loop or asyncio.get_running_loop()
        self.session_factory = session_factory
        self.protocol_factory = partial(
            LNTransport,
            prologue,
            self.session_factory,
            self.privkey,
            peer_addr=self.peer_addr
        )

    @log_exceptions
    async def create_connection(self):
        connector = self.proxy or self.loop
        return await connector.create_connection(
            self.protocol_factory,
            self.peer_addr.host,
            self.peer_addr.port
        )

    async def __aenter__(self):
        _transport, protocol = await self.create_connection()
        self.session = protocol.session
        assert isinstance(self.session, SessionBase)
        await protocol.handshake_done.wait()
        return self.session

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()


async def create_bolt8_server(
    prologue: bytes,
    privkey: bytes,
    whitelist,
    session_factory,
    host=None,
    port=None,
    *,
    loop=None,
):
    loop = loop or asyncio.get_event_loop()
    protocol_factory = partial(
        LNTransport,
        prologue,
        session_factory,
        privkey,
        whitelist=whitelist
    )
    return await loop.create_server(protocol_factory, host, port)
