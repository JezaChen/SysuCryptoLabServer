import hashlib
import os


def hex2(v):
    s = hex(v)[2:]
    return '0x' + s if len(s) % 2 == 0 else '0x0' + s


def RSAEnc(m, n, e):
    return pow(m, e, n)


def RSADec(c, n, d):
    return pow(c, d, n)


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


def oaep_encode(input_bytes: bytes, r_bytes: bytes) -> bytes:
    print("OAEP -- Encode")

    if len(input_bytes) != 128 or len(r_bytes) != 128:
        raise ValueError("Length of input_bytes or r is not 128!")

    m_int = int.from_bytes(input_bytes, byteorder="big")
    r_int = int.from_bytes(r_bytes, byteorder="big")

    x_int = m_int ^ int.from_bytes(mgf1(r_bytes, 128), byteorder="big")
    x_bytes = x_int.to_bytes(128, "big")

    y_int = r_int ^ int.from_bytes(mgf1(x_bytes, 128), byteorder="big")
    y_bytes = y_int.to_bytes(128, "big")

    print("x_bytes:{}\ny_bytes:{}".format(x_bytes, y_bytes))

    return x_bytes + y_bytes


def oaep_decode(input_bytes: bytes) -> (bytes, bytes):
    print("OAEP -- Decode")

    if len(input_bytes) != 256:
        raise ValueError("Length of input_bytes is not 256!")
    x_bytes, y_bytes = input_bytes[:128], input_bytes[128:]
    print("x_bytes:{}\ny_bytes:{}".format(x_bytes, y_bytes))

    x_int = int.from_bytes(x_bytes, "big")
    y_int = int.from_bytes(y_bytes, "big")
    r_int = int.from_bytes(mgf1(x_bytes, 128), byteorder="big") ^ y_int
    r_bytes = r_int.to_bytes(128, "big")
    m_int = x_int ^ int.from_bytes(mgf1(r_bytes, 128), byteorder="big")
    m_bytes = m_int.to_bytes(128, "big")
    return m_bytes.lstrip(b'\x00'), r_bytes


def RSAOAEPEnc(m: bytes, n: int, e: int, r: bytes = None):
    if r is None:
        r = os.urandom(128)
    if len(r) != 128:
        raise ValueError("Length of r is not 128!")
    m = b'\x00' * (128 - len(m)) + m  # pad
    encoded_msg = oaep_encode(m, r)
    encoded_msg_int = int.from_bytes(encoded_msg, "big")
    print("enc: m_int: {}".format(encoded_msg_int))
    print("bytes of m: {}".format(len(bytes.fromhex(hex2(encoded_msg_int)[2:]))))
    print(encoded_msg_int >= n)
    c_int = RSAEnc(encoded_msg_int, n, e)
    print("enc: c_int: {}".format(c_int))
    return hex2(c_int)


def RSAOAEPDec(c: bytes, n: int, d: int):
    c_int = int.from_bytes(c, "big")
    print("dec: c_int: {}".format(c_int))
    plain_text_int = RSADec(c_int, n, d)
    print("dec: m_int: {}".format(plain_text_int))
    plain_text_bytes = plain_text_int.to_bytes(256, "big")
    msg, r_bytes = oaep_decode(plain_text_bytes)
    return msg, r_bytes


msg = b"Hello"
print("Message:\t", msg)

e = int("010001", 16)
p = 70370393959675521820500782129455829046834624191193040774778174186390861020432999560509479154049871458971941351584959609981703698259784491166467017313830811268279206174600595835094806956703023301214538079175799918922889270950498970147750593045730876854838583096128502835448395964315594558492757738078102448063
q = 138546997122076233229845236559079110806642277731618790000419567680695298567304830060061354017372881645373283309640996354308746527346324698910039969835699225730201932391098735680425536942180270112225329355005519944092453869875019638296668830952322651286967291745849935332582547395526139086212637793518775176423

n = p * q
print("bytes of n: {}".format(len(bytes.fromhex(hex2(n)[2:]))))
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)

print("e: {}".format(e))
print("n: {}".format(n))
print("d: {}".format(d))

cipher_hex_str = RSAOAEPEnc(msg, n, e)
cipher_bytes = bytes.fromhex(cipher_hex_str[2:])
msg, r = RSAOAEPDec(cipher_bytes, n, d)
print(msg)
