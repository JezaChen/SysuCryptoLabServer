import functools

from flask import request, abort, jsonify

from . import main
from .rsa_es_oaep import *
from .tools import hex_to_bytes, try_decode_utf8


@main.route("/crypto/eme_oaep_encode")
def eme_oaep_encode():
    """
    参数：json
    - message: utf8/hex 字符串
    - is_message_utf8: (可选) message是否为utf8编码，默认为False
    - label: (可选) utf8/hex 字符串
    - is_label_utf8: (可选) label是否为utf8编码, 默认为False

    - hash: OAEP填充过程中的label所用到的Hash函数名称, 默认为SHA256
    - mgf1_hash: MGF1所用到的Hash函数名称, 默认为SHA256
    返回：json
    - success: 是否成功
    - encoded_message: 编码后的信息，hex编码
    - reason: 如果success=False, 失败的理由
    :return:
    """
    # 提取参数
    message = request.args.get("message")
    if message is None:
        abort(400)
    is_message_utf8 = request.args.get("is_message_utf8", "0")
    label = request.args.get("label")
    is_label_utf8 = request.args.get("is_label_utf8", "0")
    hash_func_name = request.args.get("hash", "sha256")
    mgf1_hash_func_name = request.args.get("mgf1_hash", "sha256")

    # 检查哈希函数
    if hash_func_name.lower() not in hashlib.algorithms_available \
            or mgf1_hash_func_name.lower() not in hashlib.algorithms_available:
        return jsonify(success=False, reason="哈希函数指定错误，请检查参数hash以及mgf1_hash")

    # 检查message
    if is_message_utf8 == "1":
        message_bytes = bytes(message, encoding="utf8")
    else:
        message_bytes = hex_to_bytes(message)
        if message_bytes is None:
            return jsonify(success=False, reason="message解析错误，请检查message是否为合法的hex字符串")
    # 检查消息长度
    if len(message_bytes) > 256 - 2 * hashlib.new(hash_func_name).digest_size - 2:
        return jsonify(success=False, reason="消息过长")

    if label:
        if is_label_utf8 == "1":
            label_bytes = bytes(label, encoding="utf8")
        else:
            label_bytes = hex_to_bytes(label)
            if label_bytes is None:
                return jsonify(success=False, reason="label解析错误，请检查label是否为合法的hex字符串")
    else:
        label_bytes = b""



    rslt_bytes = oaep_encode(message_bytes, label_bytes,
                             hash_func=functools.partial(hashlib.new, hash_func_name),
                             mgf_hash_func=functools.partial(hashlib.new, mgf1_hash_func_name))

    rslt_hex_str = "0x" + rslt_bytes.hex()
    response = jsonify(encoded_message=rslt_hex_str, success=True)
    return response


@main.route("/crypto/eme_oaep_decode")
def eme_oaep_decode():
    """
    参数：json
    - encoded_message: 编码后的字符串，hex格式
    - label: (可选) utf8/hex 字符串
    - is_label_utf8: (可选) label是否为utf8编码, 默认为False

    - hash: OAEP填充过程中的label所用到的Hash函数名称, 默认为SHA256
    - mgf1_hash: MGF1所用到的Hash函数名称, 默认为SHA256

    返回：json
    - success: 是否成功
    - message_bytes: 解码后的信息，hex格式
    - message_utf8: 解码后的字符串，utf-8格式
    - reason: 如果success=False, 失败的理由
    :return:
    """
    encoded_message = request.args.get("encoded_message")
    if encoded_message is None:
        abort(400)

    label = request.args.get("label")
    is_label_utf8 = request.args.get("is_label_utf8", "0")

    hash_func_name = request.args.get("hash", "sha256")
    mgf1_hash_func_name = request.args.get("mgf1_hash", "sha256")

    encoded_message_bytes = hex_to_bytes(encoded_message)
    # 合法性检查
    if encoded_message_bytes is None:
        return jsonify(success=False, reason="encoded_message解析错误，请检查encoded_message是否为合法的hex字符串")

    if len(encoded_message_bytes) != 256:
        return jsonify(success=False, reason="所提供的编码后字符串不为256字节")

    if hash_func_name.lower() not in hashlib.algorithms_available \
            or mgf1_hash_func_name.lower() not in hashlib.algorithms_available:
        return jsonify(success=False, reason="哈希函数指定错误，请检查参数hash以及mgf1_hash")

    if label:
        if is_label_utf8 == "1":
            label_bytes = bytes(label, encoding="utf8")
        else:
            label_bytes = hex_to_bytes(label)
            if label_bytes is None:
                return jsonify(success=False, reason="label解析错误，请检查label是否为合法的hex字符串")
    else:
        label_bytes = b""

    message_bytes = oaep_decode(encoded_message_bytes, label_bytes,
                                hash_func=functools.partial(hashlib.new, hash_func_name),
                                mgf_hash_func=functools.partial(hashlib.new, mgf1_hash_func_name))

    if message_bytes is None:
        return jsonify(success=False, reason="解码失败，请检查参数")

    # 尝试解析信息为utf8
    message_utf8 = try_decode_utf8(message_bytes)

    response = jsonify(message_bytes="0x" + message_bytes.hex(), message_utf8=message_utf8, success=True)
    return response


@main.route("/crypto/rsaes_2048_oaep/enc")
def rsaes_oaep_enc():
    """
    参数：json
    - message: utf8/hex 字符串
    - is_message_utf8: (可选) message是否为utf8编码，默认为False
    - n: hex字符串
    - e: hex字符串
    - label: (可选) utf8/hex 字符串
    - is_label_utf8: (可选) label是否为utf8编码, 默认为False

    - hash: OAEP填充过程中的label所用到的Hash函数名称, 默认为SHA256
    - mgf1_hash: MGF1所用到的Hash函数名称, 默认为SHA256

    返回：json
    - success: 是否成功
    - cipher_bytes: hex编码的密文
    - reason: 如果success=False, 失败的理由
    :return:
    """
    message_str = request.args.get("message")
    is_message_utf8 = request.args.get("is_message_utf8", "0")
    n_hex = request.args.get("n")
    e_hex = request.args.get("e")
    label_str = request.args.get("label")
    is_label_utf8 = request.args.get("is_label_utf8", "0")

    hash_func_name = request.args.get("hash", "sha256")
    mgf1_hash_func_name = request.args.get("mgf1_hash", "sha256")

    # 检查两个Hash函数是否合法
    if hash_func_name.lower() not in hashlib.algorithms_available \
            or mgf1_hash_func_name.lower() not in hashlib.algorithms_available:
        return jsonify(success=False, reason="哈希函数指定错误，请检查参数hash以及mgf1_hash")

    if message_str is None or n_hex is None or e_hex is None:
        abort(400)

    # 处理message
    if is_message_utf8 == "1":
        message_bytes = bytes(message_str, encoding="utf8")
    else:
        message_bytes = hex_to_bytes(message_str)
        if message_bytes is None:
            return jsonify(success=False, reason="message解析错误，请检查message是否为合法的hex字符串")
    # 检查消息长度
    if len(message_bytes) > 256 - 2 * hashlib.new(hash_func_name).digest_size - 2:
        return jsonify(success=False, reason="消息过长")

    # 处理label
    if label_str:
        if is_label_utf8 == "1":
            label_bytes = bytes(label_str, encoding="utf8")
        else:
            label_bytes = hex_to_bytes(label_str)
            if label_bytes is None:
                return jsonify(success=False, reason="label解析错误，请检查label是否为合法的hex字符串")
    else:
        label_bytes = b""

    # 处理n, e
    n_bytes = hex_to_bytes(n_hex)
    e_bytes = hex_to_bytes(e_hex)

    # 合法性检查
    if n_bytes is None:
        return jsonify(success=False, reason="n解析错误，请检查n是否为合法的hex字符串")
    if e_bytes is None:
        return jsonify(success=False, reason="e解析错误，请检查e是否为合法的hex字符串")

    n_int = int.from_bytes(n_bytes, byteorder="big")
    e_int = int.from_bytes(e_bytes, byteorder="big")
    if e_int >= n_int:
        return jsonify(success=False, reason="e >= n，请检查参数")

    # 合法性检查通过, 开始加密
    cipher_hex = RSAOAEPEnc(message_bytes, n_int, e_int, label_bytes,
                            hash_func=functools.partial(hashlib.new, hash_func_name),
                            mgf1_hash_func=functools.partial(hashlib.new, mgf1_hash_func_name)
                            )
    return jsonify(success=True, cipher_bytes=cipher_hex)


@main.route("/crypto/rsaes_2048_oaep/dec")
def rsaes_oaep_dec():
    """
    参数：json
    - cipher: hex编码的字符串
    - n: hex字符串
    - d: hex字符串
    - label: (可选) utf8/hex 字符串
    - is_label_utf8: (可选) label是否为utf8编码, 默认为False

    - hash: OAEP填充过程中的label所用到的Hash函数名称, 默认为SHA256
    - mgf1_hash: MGF1所用到的Hash函数名称, 默认为SHA256

    返回：json
    - success: 是否成功
    - message_bytes: hex编码的明文
    - message_utf8:（如果解码成功）UTF-8编码的明文
    - reason: 如果success=False, 失败的理由
    :return:
    """
    cipher_hex = request.args.get("cipher")
    n_hex = request.args.get("n")
    d_hex = request.args.get("d")
    label_str = request.args.get("label")
    is_label_utf8 = request.args.get("is_label_utf8", "0")

    hash_func_name = request.args.get("hash", "sha256")
    mgf1_hash_func_name = request.args.get("mgf1_hash", "sha256")

    # 检查两个Hash函数是否合法
    if hash_func_name.lower() not in hashlib.algorithms_available \
            or mgf1_hash_func_name.lower() not in hashlib.algorithms_available:
        return jsonify(success=False, reason="哈希函数指定错误，请检查参数hash以及mgf1_hash")

    if cipher_hex is None or n_hex is None or d_hex is None:
        abort(400)

    cipher_bytes = hex_to_bytes(cipher_hex)

    # cipher合法性检查
    if cipher_bytes is None:
        return jsonify(success=False, reason="cipher_bytes解析错误，请检查cipher_bytes是否为合法的hex字符串")
    if len(cipher_bytes) != 256:
        return jsonify(success=False, reason="密文长度不等于256字节（2048bit）")

    # 处理label
    if label_str:
        if is_label_utf8 == "1":
            label_bytes = bytes(label_str, encoding="utf8")
        else:
            label_bytes = hex_to_bytes(label_str)
            if label_bytes is None:
                return jsonify(success=False, reason="label解析错误，请检查label是否为合法的hex字符串")
    else:
        label_bytes = b""

    n_bytes = hex_to_bytes(n_hex)
    d_bytes = hex_to_bytes(d_hex)

    # n, d合法性检查
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

    # 合法性检查通过, 开始解密
    message_bytes = RSAOAEPDec(cipher_bytes, n_int, d_int, label_bytes,
                               hash_func=functools.partial(hashlib.new, hash_func_name),
                               mgf1_hash_func=functools.partial(hashlib.new, mgf1_hash_func_name)
                               )

    if message_bytes is None:
        return jsonify(success=False, reason="解码失败，请检查参数")
    # 尝试解析信息为utf8
    message_utf8 = try_decode_utf8(message_bytes)
    return jsonify(success=True, message_bytes="0x" + message_bytes.hex(), message_utf8=message_utf8)
