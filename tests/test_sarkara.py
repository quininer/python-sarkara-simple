#!/usr/bin/env python

from random import getrandbits, randrange
from libsarkara import (
    CryptoException,
    ascon_encrypt, ascon_decrypt,
    newhope_keygen, newhope_exchange, newhope_exchange_from,
    bliss_keygen, bliss_sign, bliss_verify,
    argon2i_derive, argon2i_verify,
    bhmac_result, bhmac_verify
)


def randbytes(size: int) -> bytes:
    return getrandbits(size * 8).to_bytes(size, 'little')


class Test:
    def test_encrypt(self):
        key = randbytes(16)
        nonce = randbytes(16)
        aad = randbytes(32)
        data = randbytes(64)

        out = ascon_encrypt(key, nonce, aad, data)
        assert data == ascon_decrypt(key, nonce, aad, out)

        try:
            ascon_decrypt(key[:-1] + bytes([key[-1] ^ 1]), nonce, aad, out)
            assert False
        except CryptoException:
            pass

        try:
            ascon_decrypt(key, nonce, aad, out[:-1] + bytes([out[-1] ^ 1]))
            assert False
        except CryptoException:
            pass

    def test_kex(self):
        sk, pk = newhope_keygen()
        out, rec = newhope_exchange(pk)

        assert out == newhope_exchange_from(sk, rec)
        assert out != newhope_exchange_from(bytes([sk[0] ^ 1]) + sk[1:], rec)
        assert out != newhope_exchange_from(sk, bytes([rec[0] ^ 1]) + rec[1:])

        try:
            newhope_exchange(pk[:-1])
            assert False
        except CryptoException:
            pass

        try:
            newhope_exchange_from(sk, rec[:-1])
            assert False
        except CryptoException:
            pass

    def test_sign(self):
        data = randbytes(64)
        sk, pk = bliss_keygen()
        sign = bliss_sign(sk, data)

        assert bliss_verify(pk, sign, data)
        assert not bliss_verify(pk, sign, bytes(data[0] ^ 1) + data[1:])
        assert not bliss_verify(pk, bytes([sign[0] ^ 1]) + sign[1:], data)
        assert not bliss_verify(bytes([pk[0] ^ 1]) + pk[1:], sign, data)

        try:
            bliss_sign(sk[1:], data)
            assert False
        except CryptoException:
            pass

        try:
            bliss_verify(pk[1:], sign, data)
            assert False
        except CryptoException:
            pass

        try:
            bliss_verify(pk, sign[1:], data)
            assert False
        except CryptoException:
            pass

    def test_pwhash(self):
        key = randbytes(16)
        aad = randbytes(32)
        salt = randbytes(12)
        password = randbytes(8)
        length = randrange(16, 64)

        out = argon2i_derive(key, aad, salt, password, length)
        assert len(out) == length
        assert out == argon2i_derive(key, aad, salt, password, length)
        assert argon2i_verify(key, aad, salt, password, out)
        assert not argon2i_verify(
            bytes([key[0] ^ 1]) + key[1:],
            aad, salt, password, out
        )
        assert not argon2i_verify(
            key, aad, salt,
            bytes([password[0] ^ 1]) + password[1:],
            out
        )

        try:
            argon2i_derive(key, aad, randbytes(7), password, length)
            assert False
        except CryptoException:
            pass

        try:
            argon2i_verify(key, aad, salt, password, randbytes(3))
            assert False
        except CryptoException:
            pass

    def test_auth(self):
        key = randbytes(32)
        nonce = randbytes(32)
        data = randbytes(64)
        length = randrange(16, 64)

        out = bhmac_result(key, nonce, data, length)
        assert len(out) == length
        assert out == bhmac_result(key, nonce, data, length)
        assert bhmac_verify(key, nonce, data, out)
        assert not bhmac_verify(
            bytes([key[0] ^ 1]) + key[1:],
            nonce, data, out
        )
        assert not bhmac_verify(
            key, nonce, data,
            bytes([out[0] ^ 1]) + out[1:]
        )
        assert not bhmac_verify(
            key, nonce,
            bytes([data[0] ^ 1]) + data[1:],
            out
        )
