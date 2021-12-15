import hashlib

from app.main.dsa.core import generate_params, generate_key_pair, sign


def hack_core(delta1: int, gamma1: int, msg_digest1: int, delta2: int, gamma2: int, msg_digest2: int, q: int):
    try:
        k = (((msg_digest1 - msg_digest2) % q) * (pow(delta1 - delta2, -1, q) % q)) % q
        priv = (((((delta1 * k) % q) - msg_digest1) % q) * pow(gamma1, -1, q)) % q
        return k, priv
    except Exception as e:
        return None


def main():
    p, q, g = generate_params()
    private_key, public_key = generate_key_pair(p, q, g)
    k = 2
    msg1 = b"hello"
    msg2 = b"ccccc"
    msg1_digest = int.from_bytes(hashlib.sha256(msg1).digest(), "big")
    msg2_digest = int.from_bytes(hashlib.sha256(msg2).digest(), "big")
    gamma1, delta1 = sign(p, q, g, private_key, msg1, k)
    gamma2, delta2 = sign(p, q, g, private_key, msg2, k)
    print("k, private_key:", hack_core(delta1, gamma1, msg1_digest, delta2, gamma2, msg2_digest, q))
    print("private_key(true): ", private_key)


if __name__ == '__main__':
    main()
