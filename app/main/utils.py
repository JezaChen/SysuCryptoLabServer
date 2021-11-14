import sympy
from flask import request, abort, jsonify, make_response
from flask_cors import cross_origin

from . import main
from .tools import hex_to_dec_int, hex2


@main.route('/crypto/next_prime')
@cross_origin()
def get_next_prime():
    """
    获得下一个素数
    返回：text/plain
    :return:
    """
    num = request.args.get("num")
    if num is None:
        abort(400)

    if not num.isdigit():
        return "argument num must be a number", 400
    try:
        num = int(num)
        rslt = sympy.nextprime(num)
        response = make_response(str(rslt))
        return response
    except TypeError:
        return "Bad Request", 400


@main.route('/crypto/calculate_inverse')
@cross_origin()
def calculate_inverse():
    """
    求解num的模mod逆元
    参数 json
    - num: 十进制表示/十六进制表示的数字
    - is_num_dec: num是否是十进制表示的数字, 默认False

    - mod: 模，十进制表示/十六进制表示的数字
    - is_mod_dec: 默认False
    返回 json
    - result_dec: 结果的十进制表示法
    - result_hex: 结果的十六进制表示法
    - success: 是否成功
    - reason: 如果不成功, 返回理由
    :return:
    """
    num_str = request.args.get("num")
    is_num_dec = request.args.get("is_num_dec", "0")
    mod_str = request.args.get("mod")
    is_mod_dec = request.args.get("is_mod_dec", "0")

    if num_str is None or mod_str is None:
        abort(400)

    # 统一为处理num为int
    if is_num_dec == "1":
        if not num_str.isdigit():
            return "argument num must be a number", 400
        num = int(num_str)
    else:  # hex
        num = hex_to_dec_int(num_str)
        if num is None:
            return "num解析错误，请检查num是否为合法的hex字符串", 400

    # 统一为处理mod为int
    if is_mod_dec == "1":
        if not mod_str.isdigit():
            return "argument mod must be a number", 400
        mod = int(mod_str)
    else:  # hex
        mod = hex_to_dec_int(mod_str)
        if mod is None:
            return "mod解析错误，请检查mod是否为合法的hex字符串", 400
    try:
        result = pow(num, -1, mod)
        result_dec = str(result)
        result_hex = hex2(result)
        return jsonify(success=True, result_dec=result_dec, result_hex=result_hex)
    except ValueError:
        return jsonify(success=False, reason="{}在模{}下没有逆元".format(num, mod))
