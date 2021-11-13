import hashlib
import os

from .tools import bytes_xor, hex2
from .rsa_raw import RSAEnc, RSADec
from .mgf import mgf1


def oaep_encode(M: bytes, label: bytes = b"", hash_func=hashlib.sha256, mgf_hash_func=hashlib.sha256) -> bytes:
    # 定义长度参数
    mLen = len(M)
    k = 256
    hLen = hash_func().digest_size

    lHash = hash_func(label).digest()
    PS = b"\x00" * (k - mLen - 2 * hLen - 2)
    DB = lHash + PS + b"\x01" + M

    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1, mgf_hash_func)
    maskedDB = bytes_xor(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen, mgf_hash_func)
    maskedSeed = bytes_xor(seed, seedMask)

    EM = b"\x00" + maskedSeed + maskedDB
    return EM


def oaep_decode(EM: bytes, label: bytes = b"", hash_func=hashlib.sha256, mgf_hash_func=hashlib.sha256):
    # 定义长度参数
    k = 256
    hLen = hash_func().digest_size

    lHash = hash_func(label).digest()
    Y, maskedSeed, maskedDB = EM[:1], EM[1:1 + hLen], EM[1 + hLen:]
    seedMask = mgf1(maskedDB, hLen, mgf_hash_func)
    seed = bytes_xor(maskedSeed, seedMask)
    dbMask = mgf1(seed, k - hLen - 1, mgf_hash_func)
    DB = bytes_xor(maskedDB, dbMask)

    lHash_prime = DB[:hLen]
    if lHash_prime != lHash:  # Hash不匹配, 解码失败
        return None
    DB_without_lHash = DB[hLen:]
    M = DB_without_lHash.strip(b"\x00")  # 去掉PS
    if M[0] != 1:  # 0x01
        return None
    M = M[1:]  # 除掉0x01
    return M


def RSAOAEPEnc(m: bytes, n: int, e: int, l: bytes = b"", hash_func=hashlib.sha256, mgf1_hash_func=hashlib.sha256):
    encoded_msg = oaep_encode(m, l,
                              hash_func=hash_func,
                              mgf_hash_func=mgf1_hash_func)
    encoded_msg_int = int.from_bytes(encoded_msg, "big")
    c_int = RSAEnc(encoded_msg_int, n, e)
    return hex2(c_int)


def RSAOAEPDec(c: bytes, n: int, d: int, l: bytes = b"", hash_func=hashlib.sha256, mgf1_hash_func=hashlib.sha256):
    c_int = int.from_bytes(c, "big")
    plain_text_int = RSADec(c_int, n, d)
    plain_text_bytes = plain_text_int.to_bytes(256, "big")
    msg = oaep_decode(plain_text_bytes, l,
                      hash_func=hash_func,
                      mgf_hash_func=mgf1_hash_func)
    return msg


def test():
    msg = b"chenjianzhang"
    print("Message:\t", msg)

    e = int("010001", 16)
    p = 70370393959675521820500782129455829046834624191193040774778174186390861020432999560509479154049871458971941351584959609981703698259784491166467017313830811268279206174600595835094806956703023301214538079175799918922889270950498970147750593045730876854838583096128502835448395964315594558492757738078102448063
    q = 138546997122076233229845236559079110806642277731618790000419567680695298567304830060061354017372881645373283309640996354308746527346324698910039969835699225730201932391098735680425536942180270112225329355005519944092453869875019638296668830952322651286967291745849935332582547395526139086212637793518775176423

    n = p * q

    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)

    cipher_hex_str = RSAOAEPEnc(msg, n, e)
    cipher_bytes = bytes.fromhex(cipher_hex_str[2:])
    msg = RSAOAEPDec(cipher_bytes, n, d)

    print(hex2(n))
    print(hex2(e))
    print(hex2(d))
    print(msg)


if __name__ == '__main__':
    test()