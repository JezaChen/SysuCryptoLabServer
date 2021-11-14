import os
from .tools import bytes_xor, hex2
from .rsa_raw import RSAEnc, RSADec
from .mgf import mgf1


def g(input_str: bytes):
    rslt = mgf1(input_str, 128)
    return b"\x00\x00" + rslt[2:]  # 将前两个字节置0


def oaep_encode(input_bytes: bytes, r_bytes: bytes) -> bytes:
    if len(input_bytes) != 128 or len(r_bytes) != 128:
        raise ValueError("Length of input_bytes or r is not 128!")

    m_int = int.from_bytes(input_bytes, byteorder="big")
    r_int = int.from_bytes(r_bytes, byteorder="big")

    x_int = m_int ^ int.from_bytes(g(r_bytes), byteorder="big")
    x_bytes = x_int.to_bytes(128, "big")

    y_int = r_int ^ int.from_bytes(g(x_bytes), byteorder="big")
    y_bytes = y_int.to_bytes(128, "big")

    return x_bytes + y_bytes


def oaep_decode(input_bytes: bytes) -> (bytes, bytes):
    if len(input_bytes) != 256:
        raise ValueError("Length of input_bytes is not 256!")
    x_bytes, y_bytes = input_bytes[:128], input_bytes[128:]

    x_int = int.from_bytes(x_bytes, "big")
    y_int = int.from_bytes(y_bytes, "big")
    r_int = int.from_bytes(g(x_bytes), byteorder="big") ^ y_int
    r_bytes = r_int.to_bytes(128, "big")
    m_int = x_int ^ int.from_bytes(g(r_bytes), byteorder="big")
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

    c_int = RSAEnc(encoded_msg_int, n, e)
    return hex2(c_int)


def RSAOAEPDec(c: bytes, n: int, d: int):
    c_int = int.from_bytes(c, "big")
    plain_text_int = RSADec(c_int, n, d)
    plain_text_bytes = plain_text_int.to_bytes(256, "big")
    msg, r_bytes = oaep_decode(plain_text_bytes)
    return msg, r_bytes

def test():
    msg = b"Hello"
    print("Message:\t", msg)

    e = int("010001", 16)
    p = 70370393959675521820500782129455829046834624191193040774778174186390861020432999560509479154049871458971941351584959609981703698259784491166467017313830811268279206174600595835094806956703023301214538079175799918922889270950498970147750593045730876854838583096128502835448395964315594558492757738078102448063
    q = 138546997122076233229845236559079110806642277731618790000419567680695298567304830060061354017372881645373283309640996354308746527346324698910039969835699225730201932391098735680425536942180270112225329355005519944092453869875019638296668830952322651286967291745849935332582547395526139086212637793518775176423

    n = p * q

    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)


    cipher_hex_str = RSAOAEPEnc(msg, n, e)
    cipher_bytes = bytes.fromhex(cipher_hex_str[2:])
    msg, r = RSAOAEPDec(cipher_bytes, n, d)

    print(hex2(n))
    print(hex2(e))
    print(hex2(d))