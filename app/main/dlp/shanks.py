import math

from app.main.tools import mul_order


def find_pair(L1, L2):
    L1_ptr = 0
    L2_ptr = 0
    while L1_ptr < len(L1) and L2_ptr < len(L2):
        if L1[L1_ptr][1] == L2[L2_ptr][1]:
            return L1[L1_ptr], L2[L2_ptr]
        if L1[L1_ptr][1] > L2[L2_ptr][1]:
            L2_ptr += 1
        else:
            L1_ptr += 1
    return None


def shanks(p, n, alpha, beta):
    m = math.ceil(math.sqrt(n))
    L1 = []
    for j in range(0, m):
        L1.append((j, pow(alpha, m * j, p)))
    L1.sort(key=lambda item: item[1])

    L2 = []
    for i in range(0, m):
        L2.append((i, beta * pow(alpha, -i, p) % p))
    L2.sort(key=lambda item: item[1])
    rslt = find_pair(L1, L2)
    if rslt is None:
        return None

    [j, _], [i, _] = rslt
    return (m * j + i) % n


def solve_dlp(alpha, beta, p):
    n = mul_order(alpha, p)
    return shanks(p, n, alpha, beta)


if __name__ == '__main__':
    print(solve_dlp(3, 525, 809))
