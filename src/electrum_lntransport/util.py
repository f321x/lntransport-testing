import asyncio
import re
from functools import wraps
from asyncio import iscoroutinefunction, CancelledError
from logging import getLogger
from typing import Tuple, Optional

from aiorpcx.util import NetAddress
from aiorpcx import SOCKSProxy


_logger = getLogger('electrum_lntransport')


class ConnStringFormatError(Exception): pass


def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def log_exceptions(func):
    """Decorator to log AND re-raise exceptions."""
    assert iscoroutinefunction(func), 'func needs to be a coroutine'

    @wraps(func)
    async def wrapper(*args, **kwargs):
        self = args[0] if len(args) > 0 else None
        try:
            return await func(*args, **kwargs)
        except CancelledError as e:
            raise
        except BaseException as e:
            mylogger = self.logger if hasattr(self, 'logger') else _logger
            try:
                mylogger.exception(f"Exception in {func.__name__}: {repr(e)}")
            except BaseException as e2:
                print(f"logging exception raised: {repr(e2)}... orig exc: {repr(e)} in {func.__name__}")
            raise
    return wrapper


# partly duplicated in spesmilo/electrum
class ESocksProxy(SOCKSProxy):
    # note: proxy will not leak DNS as create_connection()
    # sets (local DNS) resolve=False by default

    async def open_connection(self, host=None, port=None, **kwargs):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        transport, _ = await self.create_connection(
            lambda: protocol, host, port, **kwargs)
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        return reader, writer


def get_bolt8_nonce_bytes(n):
    """BOLT 8 requires the nonce to be 12 bytes, 4 bytes leading
    zeroes and 8 bytes little endian encoded 64-bit integer.
    """
    return b"\x00"*4 + n.to_bytes(8, 'little')


def split_host_port(host_port: str) -> Tuple[str, str]: # port returned as string
    ipv6  = re.compile(r'\[(?P<host>[:0-9a-f]+)\](?P<port>:\d+)?$')
    other = re.compile(r'(?P<host>[^:]+)(?P<port>:\d+)?$')
    m = ipv6.match(host_port)
    if not m:
        m = other.match(host_port)
    if not m:
        raise ConnStringFormatError('Connection strings must be in <node_pubkey>@<host>:<port> format')
    host = m.group('host')
    if m.group('port'):
        port = m.group('port')[1:]
    else:
        port = '9735'
    try:
        int(port)
    except ValueError:
        raise ConnStringFormatError('Port number must be decimal')
    return host, port


def extract_nodeid(connect_contents: str) -> Tuple[bytes, Optional[str]]:
    """Takes a connection-string-like str, and returns a tuple (node_id, rest),
    where rest is typically a host (with maybe port). Examples:
    - extract_nodeid(pubkey@host:port) == (pubkey, host:port)
    - extract_nodeid(pubkey@host) == (pubkey, host)
    - extract_nodeid(pubkey) == (pubkey, None)
    Can raise ConnStringFormatError.
    """
    rest = None
    try:
        # connection string?
        nodeid_hex, rest = connect_contents.split("@", 1)
    except ValueError:
        # node id as hex?
        nodeid_hex = connect_contents
    if rest == '':
        raise ConnStringFormatError('At least a hostname must be supplied after the at symbol.')
    try:
        node_id = bytes.fromhex(nodeid_hex)
        if len(node_id) != 33:
            raise Exception()
    except Exception:
        raise ConnStringFormatError('Invalid node ID, must be 33 bytes and hexadecimal')
    return node_id, rest


class LNPeerAddr:
    # note: while not programmatically enforced, this class is meant to be *immutable*

    def __init__(self, host: str, port: int, pubkey: bytes):
        assert isinstance(host, str), repr(host)
        assert isinstance(port, int), repr(port)
        assert isinstance(pubkey, bytes), repr(pubkey)
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct LNPeerAddr: invalid host or port (host={host}, port={port})") from e
        # note: not validating pubkey as it would be too expensive:
        # if not ECPubkey.is_pubkey_bytes(pubkey): raise ValueError()
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self._net_addr = net_addr

    def __str__(self):
        return '{}@{}'.format(self.pubkey.hex(), self.net_addr_str())

    @classmethod
    def from_str(cls, s):
        node_id, rest = extract_nodeid(s)
        host, port = split_host_port(rest)
        return LNPeerAddr(host, int(port), node_id)

    def __repr__(self):
        return f'<LNPeerAddr host={self.host} port={self.port} pubkey={self.pubkey.hex()}>'

    def net_addr(self) -> NetAddress:
        return self._net_addr

    def net_addr_str(self) -> str:
        return str(self._net_addr)

    def __eq__(self, other):
        if not isinstance(other, LNPeerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.pubkey == other.pubkey)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.host, self.port, self.pubkey))
