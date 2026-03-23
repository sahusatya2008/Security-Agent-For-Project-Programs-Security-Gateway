from __future__ import annotations

import os
import secrets


def bit_flip(data: bytes, flips: int = 3) -> bytes:
    if not data:
        return data
    data = bytearray(data)
    for _ in range(min(flips, len(data))):
        idx = secrets.randbelow(len(data))
        bit = 1 << secrets.randbelow(8)
        data[idx] ^= bit
    return bytes(data)


def dictionary_insertion(data: bytes) -> bytes:
    tokens = [b"%x%x%x", b"' OR 1=1 --", b"../../../../etc/passwd", os.urandom(4)]
    token = secrets.choice(tokens)
    pos = secrets.randbelow(len(data) + 1)
    return data[:pos] + token + data[pos:]


def structure_mutation(data: bytes) -> bytes:
    if len(data) < 2:
        return data + b"A"
    cut = secrets.randbelow(len(data) - 1) + 1
    return data[cut:] + data[:cut]
