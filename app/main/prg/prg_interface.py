from flask import request, jsonify
from flask_cors import cross_origin

from app.main import main
from app.main.prg.core import tiny_random_generator


@main.route('/crypto/prg/check', methods=["POST"])
@cross_origin()
def check_result():
    """
    校验结果是否正确
    返回：text/plain
    :return: json
    - success: 运行状态
    - matched: 结果是否匹配
    """
    seed = request.form.get('seed')
    bits = request.form.get('bits')

    if seed is None or bits is None:
        return jsonify(success=False, reason="参数不全")

    if not seed.isdigit():
        return jsonify(success=False, reason="seed不是十进制整数")

    if len(bits) != 512:
        return jsonify(success=False, reason="输出的比特串的长度不是512比特")

    try:
        seed = int(seed)
        result, _ = tiny_random_generator(seed)
        return jsonify(success=True, matched=(result == bits))
    except Exception as e:
        return jsonify(success=False, reason="程序内部错误:{}".format(e))


@main.route('/crypto/prg/detailed_output_prev_64bits', methods=["POST"])
@cross_origin()
def detailed_output_prev_64bits():
    """
    获取前64bit的详细数据
    返回：text/plain
    :return:
    - success: 运行状态
    - output: list, 元素为一个tuple (i, si, zi)
    """
    seed = request.form.get('seed')

    if seed is None:
        return jsonify(success=False, reason="参数不全")

    if not seed.isdigit():
        return jsonify(success=False, reason="seed不是十进制整数")

    try:
        seed = int(seed)
        result, _, detailed_output = tiny_random_generator(seed, output_len=64, detailed=True)
        return jsonify(success=True, detailed_output=detailed_output)
    except Exception as e:
        return jsonify(success=False, reason="程序内部错误:{}".format(e))
