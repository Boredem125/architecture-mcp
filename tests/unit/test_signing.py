from __future__ import annotations

from sandbox.crypto.signing import (
    KeyManager,
    compute_hash,
    sign_message,
    verify_signature,
)


class TestComputeHash:
    def test_deterministic(self):
        h1 = compute_hash(b"hello world")
        h2 = compute_hash(b"hello world")
        assert h1 == h2

    def test_different_inputs(self):
        h1 = compute_hash(b"hello")
        h2 = compute_hash(b"world")
        assert h1 != h2

    def test_hex_format(self):
        h = compute_hash(b"test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestKeyManager:
    def test_generate_keypair(self):
        km = KeyManager()
        km.generate_keypair("test-agent")
        assert km.get_signing_key("test-agent") is not None
        assert km.get_verify_key("test-agent") is not None

    def test_sign_and_verify(self):
        km = KeyManager()
        km.generate_keypair("agent-1")
        data = b"important message"
        sk = km.get_signing_key("agent-1")
        vk = km.get_verify_key("agent-1")
        sig = sign_message(data, sk)
        assert verify_signature(data, sig, vk)

    def test_tampered_data_fails(self):
        km = KeyManager()
        km.generate_keypair("agent-1")
        sk = km.get_signing_key("agent-1")
        vk = km.get_verify_key("agent-1")
        sig = sign_message(b"original", sk)
        assert not verify_signature(b"tampered", sig, vk)

    def test_wrong_key_fails(self):
        km = KeyManager()
        km.generate_keypair("agent-1")
        km.generate_keypair("agent-2")
        sk1 = km.get_signing_key("agent-1")
        vk2 = km.get_verify_key("agent-2")
        sig = sign_message(b"data", sk1)
        assert not verify_signature(b"data", sig, vk2)
