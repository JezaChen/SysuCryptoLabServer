from functools import reduce
from math import gcd


def bytes_xor(var, key, byteorder="big"):
    key, var = key[:len(var)], var[:len(key)]
    int_var = int.from_bytes(var, byteorder)
    int_key = int.from_bytes(key, byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), byteorder)


def hex2(v: int):
    s = hex(v)[2:]
    return '0x' + s if len(s) % 2 == 0 else '0x0' + s


def hex_to_bytes(hex_str: str):
    try:
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        rslt = bytes.fromhex(hex_str)
        return rslt
    except ValueError:
        return None


def hex_to_dec_int(hex_str: str):
    try:
        rslt = int(hex_str, 16)
        return rslt
    except ValueError:
        return None


def try_decode_utf8(raw_bytes: bytes):
    try:
        message_utf8 = raw_bytes.decode(encoding="utf8")
    except UnicodeDecodeError:
        message_utf8 = ""
    return message_utf8


def lcm(a, b):
    return (a * b) // gcd(a, b)


def is_prime(p):
    return (p > 1) and all(f == p for f, e in factored(p))


primeList = [2, 3, 5, 7]


def primes():
    p = 1
    for p in primeList:
        yield p
    while 1:
        p += 2
        while not is_prime(p):
            p += 2
        primeList.append(p)
        yield p


def factored(a):
    """
    对a进行因式分解，使用生成器的方式返回元组(p, e)，其中p是素数，e是p的幂次
    a = p0^e0 + ... + pn^en
    :param a:
    :return:
    """
    for p in primes():
        j = 0
        while a % p == 0:
            a //= p
            j += 1
        if j > 0:
            yield p, j
        if a < p * p:
            break
    if a > 1:
        yield a, 1


def multOrdr1(a, r):
    p, e = r
    m = p ** e
    t = (p - 1) * (p ** (e - 1))  # 欧拉函数在p^e上的值Phi(p**e) where p prime
    # a^t (mod m) == 1, t = phi(m)
    # 下面对t进行因式分解，找到满足a^q (mod m) == 1的phi(m)的最小因子t
    qs = [1, ]  # qs其实就是t的所有因子
    for f in factored(t):
        qs = [q * f[0] ** j for j in range(1 + f[1]) for q in qs]
    qs.sort()

    for q in qs:
        if pow(a, q, m) == 1:
            return q
    return None


def mul_order(a, m):
    if not gcd(a, m) == 1:
        return None
    mofs = (multOrdr1(a, r) for r in factored(m))  # mofs指的是m的所有(p, e)中，a关于p^e的order
    return reduce(lcm, mofs, 1)  # 求这些order的最小公倍数即可


def chinese_remainder(m_list, a_list):
    M = reduce(lambda acc, b: acc * b, m_list)  # M=m_1 x m_2 x ...
    sum = 0
    for m_i, a_i in zip(m_list, a_list):
        M_i = M // m_i
        t_i = pow(M_i, -1, m_i)
        sum += a_i * t_i * M_i
    return sum % M


if __name__ == "__main__":
    print(mul_order(37, 1000))  # 100
    b = 2 ** 63 - 1
    print(mul_order(2, b))  # 3748806900
    print(mul_order(17, b))  # 1499522760
    b = 100001
    print(mul_order(54, b))
    print(pow(54, mul_order(54, b), b))
    if any((1 == pow(54, r, b)) for r in range(1, mul_order(54, b))):
        print('Exists a power r < 9090 where pow(54,r,b)==1')
    else:
        print('Everything checks.')
    print(chinese_remainder([3, 4, 7], [1, 1, 0]))  # =49
