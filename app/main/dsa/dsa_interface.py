import hashlib
from typing import Union

from flask import request, jsonify
from flask_cors import cross_origin

from app.main import main
from app.main.dsa.core import generate_params, sign, verify
from app.main.dsa.hack_dsa import hack_core
from app.main.tools import hex2, hex_to_bytes


class IntConverter:
    @staticmethod
    def handle_dec(value: str, name: Union[str, None] = None) -> int:
        if value.isdigit():
            return int(value)
        else:
            raise ValueError(name + "不是合法的十进制数")

    @staticmethod
    def handle_hex(value: str, name: Union[str, None] = None) -> int:
        try:
            rslt = int(value, 16)
            return rslt
        except ValueError:
            raise ValueError(name + "不是合法的十六进制数")

    @staticmethod
    def convert(value: str, data_type: str, data_name: Union[str, None] = None) -> int:
        if not hasattr(IntConverter, "handle_" + data_type):
            raise ValueError(data_name + "的类型有误")

        return getattr(IntConverter, "handle_" + data_type)(value, data_name)


class BytesConverter:
    @staticmethod
    def handle_hex(value: str, name: Union[str, None] = None) -> bytes:
        rslt = hex_to_bytes(value)
        if rslt is not None:
            return rslt
        else:
            raise ValueError(name + "不是合法的hex字符串")

    @staticmethod
    def handle_utf8(value: str, name: Union[str, None] = None) -> bytes:
        return bytes(value, encoding="utf8")

    @staticmethod
    def handle_dec(value: str, name: Union[str, None] = None) -> bytes:
        value_int = IntConverter.handle_dec(value, name)
        return value_int.to_bytes((value_int.bit_length() + 7) // 8, 'big')

    @staticmethod
    def convert(value: str, data_type: str, data_name: Union[str, None] = None) -> bytes:
        if not hasattr(BytesConverter, "handle_" + data_type):
            raise ValueError(data_name + "的类型有误")

        return getattr(BytesConverter, "handle_" + data_type)(value, data_name)


def check_all_not_none(*variables):
    for var in variables:
        if var is None:
            return False
    return True


def convert_all_data_dict_to_int(post_json: dict, *data_names) -> list:
    result = []
    for name in data_names:
        if name not in post_json:
            raise ValueError("必填参数{}为空, 请检查".format(name))
        data_dict = post_json.get(name)

        data_type = data_dict.get("type", "dec")
        data_value = data_dict.get("value")  # str

        if data_value is None:
            raise ValueError("必填参数{}为空, 请检查".format(name))

        result.append(IntConverter.convert(data_value, data_type, name))
    return result


def convert_all_data_dict_to_bytes(post_json: dict, *data_names) -> list:
    result = []
    for name in data_names:
        if name not in post_json:
            raise ValueError("必填参数{}为空, 请检查".format(name))
        data_dict = post_json.get(name)

        data_type = data_dict.get("type", "utf8")
        data_value = data_dict.get("value")  # str

        if data_value is None:
            raise ValueError("必填参数{}为空, 请检查".format(name))

        result.append(BytesConverter.convert(data_value, data_type, name))
    return result


@main.route('/crypto/dsa/params', methods=["POST"])
@cross_origin()
def generate_dsa_params():
    try:
        p, q, g = generate_params()
        p_hex = hex2(p)
        q_hex = hex2(q)
        g_hex = hex2(g)
        # 课本中alpha是g
        return jsonify(success=True, p=str(p), q=str(q), alpha=str(g), p_hex=p_hex, q_hex=q_hex, alpha_hex=g_hex)
    except Exception as e:
        return jsonify(success=False, reason=str(e))


@main.route('/crypto/dsa/sign', methods=["POST"])
@cross_origin()
def dsa_sign():
    post_data = request.get_json()
    try:
        p, q, alpha, a = convert_all_data_dict_to_int(post_data, "p", "q", "alpha", "a")
    except Exception as e:
        return jsonify(success=False, reason=str(e))

    msg = post_data.get('msg')
    if msg is None:
        return jsonify(success=False, reason="参数msg为空, 请检查")
    msg_type = msg.get("type", "utf8")
    msg_value = msg.get("value")
    if msg_value is None:
        return jsonify(success=False, reason="参数msg为空, 请检查")
    try:
        msg_bytes = BytesConverter.convert(msg_value, msg_type, "msg")
    except Exception as e:
        return jsonify(success=False, reason=str(e))

    k = post_data.get('k')
    if k is not None:
        k_type = k.get("type", "dec")
        k_value = k.get("value")
        if k_value is None:
            return jsonify(success=False, reason="参数k为空, 请检查")
        try:
            k = IntConverter.convert(k_value, k_type, "k")
        except Exception as e:
            return jsonify(success=False, reason=str(e))

    r_dec, s_dec = sign(p, q, alpha, a, msg_bytes, k)
    r_hex = hex2(r_dec)
    s_hex = hex2(s_dec)
    return jsonify(success=True, gamma=str(r_dec), delta=str(s_dec), gamma_hex=r_hex, delta_hex=s_hex)


@main.route('/crypto/dsa/verify', methods=["POST"])
@cross_origin()
def dsa_verify():
    post_data = request.get_json()
    try:
        p, q, alpha, beta, r, s = convert_all_data_dict_to_int(post_data, "p", "q", "alpha", "beta", "gamma", "delta")
    except Exception as e:
        return jsonify(success=False, reason=str(e))

    msg = post_data.get('msg')
    if msg is None:
        return jsonify(success=False, reason="参数msg为空, 请检查")
    msg_type = msg.get("type", "utf8")
    msg_value = msg.get("value")
    if msg_value is None:
        return jsonify(success=False, reason="参数msg为空, 请检查")
    try:
        msg_bytes = BytesConverter.convert(msg_value, msg_type, "msg")
    except Exception as e:
        return jsonify(success=False, reason=str(e))

    result = verify(p, q, alpha, beta, msg_bytes, (r, s))

    return jsonify(success=True, verify_result=result)


@main.route('/crypto/dsa/hack_same_k', methods=['POST'])
@cross_origin()
def hack_same_k():
    post_data = request.get_json()
    try:
        q, delta1, gamma1, delta2, gamma2 = convert_all_data_dict_to_int(post_data, "q", "delta1", "gamma1", "delta2",
                                                                         "gamma2")
        if gamma1 != gamma2:
            return jsonify(success=False, reason="gamma1不等于gamma2, 意味着k不一样, 无法破解")
        msg1_bytes, msg2_bytes = convert_all_data_dict_to_bytes(post_data, "msg1", "msg2")
        msg1_digest = int.from_bytes(hashlib.sha256(msg1_bytes).digest(), "big")
        msg2_digest = int.from_bytes(hashlib.sha256(msg2_bytes).digest(), "big")
        result = hack_core(delta1, gamma1, msg1_digest, delta2, gamma2, msg2_digest, q)
        if result is None:
            return jsonify(success=False, reason="破解失败, 请检查参数")
        k_dec, private_key_dec = result
        k_hex, private_key_hex = hex2(k_dec), hex2(private_key_dec)
        return jsonify(success=True,
                       k=str(k_dec),
                       private_key=str(private_key_dec),
                       k_hex=k_hex,
                       private_key_hex=private_key_hex)

    except Exception as e:
        return jsonify(success=False, reason=str(e))
