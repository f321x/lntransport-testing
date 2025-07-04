import asyncio

import electrum_lntransport.crypto as crypto

def needs_test_with_all_chacha20_implementations(func):
    """Function decorator to run a unit test multiple times:
    once with each ChaCha20/Poly1305 implementation.

    NOTE: this is inherently sequential;
    tests running in parallel would break things
    """
    has_cryptodome = crypto.HAS_CRYPTODOME
    has_cryptography = crypto.HAS_CRYPTOGRAPHY
    if asyncio.iscoroutinefunction(func):
        async def run_test(*args, **kwargs):
            try:
                if has_cryptodome:
                    (crypto.HAS_CRYPTODOME, crypto.HAS_CRYPTOGRAPHY) = True, False
                    await func(*args, **kwargs)  # cryptodome
                if has_cryptography:
                    (crypto.HAS_CRYPTODOME, crypto.HAS_CRYPTOGRAPHY) = False, True
                    await func(*args, **kwargs)  # cryptography
            finally:
                crypto.HAS_CRYPTODOME = has_cryptodome
                crypto.HAS_CRYPTOGRAPHY = has_cryptography
    else:
        def run_test(*args, **kwargs):
            try:
                if has_cryptodome:
                    (crypto.HAS_CRYPTODOME, crypto.HAS_CRYPTOGRAPHY) = True, False
                    func(*args, **kwargs)  # cryptodome
                if has_cryptography:
                    (crypto.HAS_CRYPTODOME, crypto.HAS_CRYPTOGRAPHY) = False, True
                    func(*args, **kwargs)  # cryptography
            finally:
                crypto.HAS_CRYPTODOME = has_cryptodome
                crypto.HAS_CRYPTOGRAPHY = has_cryptography
    return run_test
