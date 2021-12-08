import hashlib
import secrets
from typing import Union

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def generate_params(key_size=2048) -> (int, int, int):
    """
    参数选择
    """
    param = dsa.generate_parameters(key_size=key_size)
    param_numbers = param.parameter_numbers()
    return param_numbers.p, param_numbers.q, param_numbers.g


def generate_key_pair(p, q, g) -> (int, int):
    private_key = secrets.randbelow(q - 1) + 1
    public_key = pow(g, private_key, p)
    return private_key, public_key


def sign(p: int, q: int, g: int, x: int, msg: bytes, k: Union[int, None] = None) -> (int, int):
    """
    签名
    x: 私钥
    """
    if k is None:
        while True:
            k = secrets.randbelow(q - 1) + 1

            r = pow(g, k, p) % q
            if r == 0:
                continue

            msg_digest_bytes = hashlib.sha256(msg).digest()
            msg_digest_int = int.from_bytes(msg_digest_bytes, "big")
            s = (pow(k, -1, q) * (msg_digest_int + x * r % q) % q) % q
            if s == 0:
                continue
            return r, s
    else:  # 给定了随机数k, 用于给同学们校验自己的
        r = pow(g, k, p) % q
        if r == 0:
            raise ValueError("r = 0")

        msg_digest_bytes = hashlib.sha256(msg).digest()
        msg_digest_int = int.from_bytes(msg_digest_bytes, "big")
        s = (pow(k, -1, q) * (msg_digest_int + x * r % q) % q) % q
        if s == 0:
            raise ValueError("s = 0")
        return r, s


def verify(p: int, q: int, g: int, y: int, msg: bytes, sig: (int, int)) -> bool:
    """
    验证签名
    y: 公钥
    """
    r, s = sig
    if not (0 < r < q and 0 < s < q):
        return False
    w = pow(s, -1, q)

    msg_digest_bytes = hashlib.sha256(msg).digest()
    msg_digest_int = int.from_bytes(msg_digest_bytes, "big")

    u1 = msg_digest_int * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def test():
    p, q, g = generate_params()
    x, y = generate_key_pair(p, q, g)
    sig = sign(p, q, g, x, b'China')
    assert verify(p, q, g, y, b'China', sig)
    print()
    print("p:{}\nq:{}\ng:{}\nx:{}\ny:{}\n".format(p, q, g, x, y))


def test_union():
    ##
    # Step 2: x, y从库中导出, 交替校验自己的签名和验证代码是否正确
    ##

    p, q, g = generate_params()
    x_param_numbers = dsa.DSAParameterNumbers(p, q, g)
    x_param = x_param_numbers.parameters()
    x_private_key = x_param.generate_private_key()
    x_public_key = x_private_key.public_key()
    x_sig = x_private_key.sign(b'China', hashes.SHA256())
    print(decode_dss_signature(x_sig))
    try:
        x_public_key.verify(x_sig, b'China', hashes.SHA256())
    except InvalidSignature as exc:
        pytest.fail(exc, pytrace=True)

    x = x_private_key.private_numbers().x
    y = x_public_key.public_numbers().y
    sig = sign(p, q, g, x, b'China')

    # 使用cryptography库检验自己的代码生成的sig是否正确
    try:
        x_public_key.verify(encode_dss_signature(*sig), b'China', hashes.SHA256())
    except InvalidSignature as exc:
        pytest.fail(exc, pytrace=True)

    # 使用自己的代码校验cryptography库的sig
    assert verify(p, q, g, y, b'China', decode_dss_signature(x_sig))


def test_union2():
    ##
    # Step 3: 自己生成密钥对x, y，校验密钥对生成有没有问题
    ##
    p, q, g = generate_params()
    x_param_numbers = dsa.DSAParameterNumbers(p, q, g)

    x, y = generate_key_pair(p, q, g)
    sig = sign(p, q, g, x, b'China')
    x_public_key = dsa.DSAPublicNumbers(y, x_param_numbers).public_key()
    x_private_key = dsa.DSAPrivateNumbers(x, dsa.DSAPublicNumbers(y, x_param_numbers)).private_key()

    x_sig = x_private_key.sign(b'China', hashes.SHA256())
    print(decode_dss_signature(x_sig))
    try:
        x_public_key.verify(x_sig, b'China', hashes.SHA256())
    except InvalidSignature as exc:
        pytest.fail(exc, pytrace=True)

    # 使用cryptography库检验自己的代码生成的sig是否正确
    try:
        x_public_key.verify(encode_dss_signature(*sig), b'China', hashes.SHA256())
    except InvalidSignature as exc:
        pytest.fail(exc, pytrace=True)

    # 使用自己的代码校验cryptography库的sig
    assert verify(p, q, g, y, b'China', decode_dss_signature(x_sig))


if __name__ == '__main__':
    test()
    test_union()
    test_union2()
