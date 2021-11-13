from flask import request, abort, jsonify

from . import main
from .rsa_simple_oaep import *
from .tools import hex_to_bytes, try_decode_utf8


@main.route("/crypto/simple_oaep_encode")
def simple_oaep_encode():
    """
    参数：json
    - message: utf8/hex 字符串
    - is_message_utf8: (可选) message是否为utf8编码，默认为False
    - r: (可选) hex编码 字符串

    返回：json
    - success: 是否成功
    - encoded_message: 编码后的信息，hex编码
    - reason: 如果success=False, 失败的理由
    :return:
    """
    message = request.args.get("message")
    is_message_utf8 = request.args.get("is_message_utf8", False)

    if message is None:
        abort(400)

    r = request.args.get("r")
    if r is None:
        r = os.urandom(128)
    else:
        r = hex_to_bytes(r)

    if r is None:
        return jsonify(success=False, reason="r解析错误，请检查r是否为合法的hex字符串")
    if len(r) != 128:
        return jsonify(success=False, reason="r的长度不等于128字节（1024bit）")

    # 检查message
    if is_message_utf8:
        message_bytes = bytes(message, encoding="utf8")
    else:
        message_bytes = hex_to_bytes(message)
        if message_bytes is None:
            return jsonify(success=False, reason="message解析错误，请检查message是否为合法的hex字符串")
    if len(message_bytes) > 128:  # 检查message长度
        return jsonify(success=False, reason="消息长度不能大于128字节")

    message_bytes = b'\x00' * (128 - len(message_bytes)) + message_bytes  # pad
    rslt_bytes = oaep_encode(message_bytes, r)
    rslt_hex_str = "0x" + rslt_bytes.hex()
    response = jsonify(encoded_message=rslt_hex_str, success=True)
    return response


@main.route("/crypto/simple_oaep_decode")
def simple_oaep_decode():
    """
    参数：json
    - encoded_message: 编码后的字符串，hex格式

    返回：json
    - success: 是否成功
    - message_bytes: 解码后的信息，hex格式
    - message_utf8: 解码后的字符串，utf-8格式
    - r: hex格式
    - reason: 如果success=False, 失败的理由
    :return:
    """
    encoded_message = request.args.get("encoded_message")
    if encoded_message is None:
        abort(400)

    encoded_message_bytes = hex_to_bytes(encoded_message)

    # 合法性检查
    if encoded_message_bytes is None:
        return jsonify(success=False, reason="encoded_message解析错误，请检查encoded_message是否为合法的hex字符串")

    if len(encoded_message_bytes) != 256:
        return jsonify(success=False, reason="所提供的编码后字符串不为256字节")

    message_bytes, r_bytes = oaep_decode(encoded_message_bytes)

    # 尝试解析信息为utf8
    message_utf8 = try_decode_utf8(message_bytes)

    response = jsonify(message_bytes="0x" + message_bytes.hex(), message_utf8=message_utf8, r="0x" + r_bytes.hex(), success=True)
    return response


@main.route("/crypto/rsa2048_simple_oaep/enc")
def rsa_simple_oaep_enc():
    """
    参数：json
    - message: utf8/hex 字符串
    - is_message_utf8: (可选) message是否为utf8编码，默认为False
    - n: hex字符串
    - e: hex字符串
    - r: (可选) hex字符串

    返回：json
    - success: 是否成功
    - cipher_bytes: hex编码的密文
    - reason: 如果success=False, 失败的理由
    :return:
    """
    message_str = request.args.get("message")
    is_message_utf8 = request.args.get("is_message_utf8", False)
    n_hex = request.args.get("n")
    e_hex = request.args.get("e")

    if message_str is None or n_hex is None or e_hex is None:
        abort(400)

    r = request.args.get("r")
    if r is None:
        r = os.urandom(128)
    else:
        r = hex_to_bytes(r)

    if r is None:
        return jsonify(success=False, reason="r解析错误，请检查r是否为合法的hex字符串")
    if len(r) != 128:
        return jsonify(success=False, reason="r的长度不等于128字节（1024bit）")

    # 处理message
    if is_message_utf8:
        message_bytes = bytes(message_str, encoding="utf8")
    else:
        message_bytes = hex_to_bytes(message_str)
        if message_bytes is None:
            return jsonify(success=False, reason="message解析错误，请检查message是否为合法的hex字符串")
    if len(message_bytes) > 128:
        return jsonify(success=False, reason="消息长度不能大于128字节")

    n_bytes = hex_to_bytes(n_hex)
    e_bytes = hex_to_bytes(e_hex)

    # 合法性检查
    if n_bytes is None:
        return jsonify(success=False, reason="n解析错误，请检查n是否为合法的hex字符串")
    if e_bytes is None:
        return jsonify(success=False, reason="e解析错误，请检查e是否为合法的hex字符串")

    if len(n_bytes) != 256:
        return jsonify(success=False, reason="n的长度不等于256字节（2048bit）")

    n_int = int.from_bytes(n_bytes, byteorder="big")
    e_int = int.from_bytes(e_bytes, byteorder="big")

    if e_int >= n_int:
        return jsonify(success=False, reason="e >= n，请检查参数")

    cipher_hex = RSAOAEPEnc(message_bytes, n_int, e_int, r)
    return jsonify(success=True, cipher_bytes=cipher_hex)


@main.route("/crypto/rsa2048_simple_oaep/dec")
def rsa_simple_oaep_dec():
    """
    参数：json
    - cipher: hex编码的字符串
    - n: hex字符串
    - d: hex字符串
    - r: (可选) hex字符串

    返回：json
    - success: 是否成功
    - message_bytes: hex编码的明文
    - message_utf8:（如果解码成功）UTF-8编码的明文
    - r: hex编码的随机数
    - reason: 如果success=False, 失败的理由
    :return:
    """
    cipher_hex = request.args.get("cipher")
    n_hex = request.args.get("n")
    d_hex = request.args.get("d")

    if cipher_hex is None or n_hex is None or d_hex is None:
        abort(400)

    cipher_bytes = hex_to_bytes(cipher_hex)
    # 合法性检查
    if cipher_bytes is None:
        return jsonify(success=False, reason="cipher_bytes解析错误，请检查cipher_bytes是否为合法的hex字符串")
    if len(cipher_bytes) != 256:
        return jsonify(success=False, reason="密文长度不等于256字节（2048bit）")

    n_bytes = hex_to_bytes(n_hex)
    d_bytes = hex_to_bytes(d_hex)

    # 合法性检查
    if n_bytes is None:
        return jsonify(success=False, reason="n解析错误，请检查n是否为合法的hex字符串")
    if d_bytes is None:
        return jsonify(success=False, reason="d解析错误，请检查d是否为合法的hex字符串")

    if len(n_bytes) != 256:
        return jsonify(success=False, reason="n的长度不等于256字节（2048bit）")

    n_int = int.from_bytes(n_bytes, byteorder="big")
    d_int = int.from_bytes(d_bytes, byteorder="big")

    if d_int >= n_int:
        return jsonify(success=False, reason="d >= n，请检查参数")

    message_bytes, r_bytes = RSAOAEPDec(cipher_bytes, n_int, d_int)
    # 尝试解析信息为utf8
    message_utf8 = try_decode_utf8(message_bytes)

    return jsonify(success=True, message_bytes="0x" + message_bytes.hex(), message_utf8=message_utf8, r="0x" + r_bytes.hex())
