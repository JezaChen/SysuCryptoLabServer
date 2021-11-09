import sympy

from . import main


@main.route('/crypto/next_prime/<num>')
def get_next_prime(num: str):
    if not num.isdigit():
        return "argument num must be a number", 400
    try:
        num = int(num)
        rslt = sympy.nextprime(num)
        return str(rslt)
    except TypeError:
        return "Bad Request", 400
