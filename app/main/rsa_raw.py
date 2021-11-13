def RSAEnc(m, n, e):
    return pow(m, e, n)


def RSADec(c, n, d):
    return pow(c, d, n)