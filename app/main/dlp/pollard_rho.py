from app.main.tools import *
import math


def pollard_rho(p, n, alpha, beta) -> (int, int, int):
    def f(_x, _a, _b):
        nonlocal p, n, alpha, beta
        sub = _x % 3  # 按照mod来划分
        if sub == 1:  # S0
            return beta * _x % p, _a, (_b + 1) % n
        elif sub == 0:  # S1
            return (_x ** 2) % p, 2 * _a % n, 2 * _b % n
        else:  # S2
            return alpha * _x % p, (_a + 1) % n, _b

    x, a, b = f(1, 0, 0)
    x_prime, a_prime, b_prime = f(x, a, b)

    while x != x_prime:
        x, a, b = f(x, a, b)
        x_prime, a_prime, b_prime = f(*f(x_prime, a_prime, b_prime))

    if math.gcd(b_prime - b, n) != 1:
        return None
    return (a - a_prime) * pow((b_prime - b), -1, n) % n


def solve_dlp(alpha, beta, p):
    n = mul_order(alpha, p)
    return pollard_rho(p, n, alpha, beta)


if __name__ == '__main__':
    ya = 3825058671964099517205471223234846245194588471680037949514700806335021383393529724195692131003753889127671117390431517299962378605270757342283339240245427141
    g = 2060700868429783091611633355344180229561388849150035417527475314898771386496110567969592724791964544803380427287644059398886410683651686798605735244265072881
    p = 5682549022748424631339131913370125786212509227588493537874673173634936008725904358935442101466555561124455782847468955028529037660533553941399408331331403379
    print(solve_dlp(g, ya, p))
