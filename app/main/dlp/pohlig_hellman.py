"""
Pohlig-Hellman 算法
"""
from app.main.tools import *


def pohlig_hellman(p, n, alpha, beta, q, c):
    j = 0
    beta_j = beta
    rslt = 0

    while j <= c - 1:
        delta = pow(beta_j, n // pow(q, j + 1), p)
        alpha_nq = pow(alpha, n // q, p)
        a_j = 0
        for i in range(0, q):
            if delta == pow(alpha_nq, i, p):
                a_j = i
                break
        # \beta_{j + 1} = \beta_j * \alpha^{-a_j * q^j}
        beta_j = beta_j * pow(alpha, -a_j * pow(q, j), p)
        rslt += a_j * pow(q, j)
        j += 1

    return rslt


def solve_dlp(alpha, beta, p):
    n = mul_order(alpha, p)
    if n is None:
        return None

    # m_list, a_list用于中国剩余定理
    m_list = []
    a_list = []

    for q, c in factored(n):  # 对n进行分解, 求出每个q^c模下的log_\alpha(\beta)
        m_list.append(pow(q, c))
        a_list.append(pohlig_hellman(p, n, alpha, beta, q, c))

    if len(m_list) == 0:
        return None

    rslt = chinese_remainder(m_list, a_list)
    return rslt


if __name__ == '__main__':
    ya = 3825058671964099517205471223234846245194588471680037949514700806335021383393529724195692131003753889127671117390431517299962378605270757342283339240245427141
    g = 2060700868429783091611633355344180229561388849150035417527475314898771386496110567969592724791964544803380427287644059398886410683651686798605735244265072881
    p = 5682549022748424631339131913370125786212509227588493537874673173634936008725904358935442101466555561124455782847468955028529037660533553941399408331331403379
    print(solve_dlp(g, ya, p))

