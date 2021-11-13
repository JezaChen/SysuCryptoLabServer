import sympy
from flask import request, abort

from . import main


@main.route('/crypto/next_prime')
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
        return str(rslt)
    except TypeError:
        return "Bad Request", 400
