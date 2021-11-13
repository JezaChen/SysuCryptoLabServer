import hashlib

def i2osp(integer: int, size: int = 4) -> bytes:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])


def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    """Mask generation function."""
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]