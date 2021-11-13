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
