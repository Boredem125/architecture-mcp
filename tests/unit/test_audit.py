from __future__ import annotations

from sandbox.audit.chain import HashChain


class TestHashChain:
    def test_genesis(self):
        chain = HashChain()
        assert chain.chain_length == 0
        assert chain.current_hash == "0" * 64

    def test_add_record(self):
        chain = HashChain()
        h = chain.add(b"first record")
        assert h != "0" * 64
        assert chain.chain_length == 1

    def test_chain_deterministic(self):
        chain1 = HashChain()
        chain2 = HashChain()
        h1 = chain1.add(b"record")
        h2 = chain2.add(b"record")
        assert h1 == h2

    def test_chain_integrity(self):
        chain = HashChain()
        records = [b"record-1", b"record-2", b"record-3"]
        hashes = []
        for r in records:
            h = chain.add(r)
            hashes.append(h)
        pairs = list(zip(records, hashes))
        assert chain.verify(pairs)

    def test_tampered_chain_fails(self):
        chain = HashChain()
        chain.add(b"record-1")
        h2 = chain.add(b"record-2")
        tampered = [(b"record-1", "bad_hash"), (b"record-2", h2)]
        assert not chain.verify(tampered)
