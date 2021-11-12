import binascii
import hashlib
import math
import sys

from Crypto.Util.number import *


def RSAEnc(m, n, e):
    return pow(m, e, n)


def RSADec(c, d, n):
    return pow(c, d, n)


def HexstringToCharacters(hexstr):
    clen = len(hexstr)

    if clen & 1 == 1:
        hexdata = hexstr[0]
        outdata = "" + chr(int(hexdata, 16))
        c = 1
    else:
        outdata = ""
        c = 0
    for i in range(c, clen, 2):
        hexdata = hexstr[i: i + 2]
        outdata = outdata + chr(int(hexdata, 16))

    return outdata


def FrmoCharacterToCode(arr):
    outdata = ""
    for i in range(len(arr)):
        outdata = outdata + chr(arr[i])
    return outdata


def MGF(seed, dLen):
    dchar = HexstringToCharacters(seed)
    c1 = int(math.floor(dLen * 1.0 / 20))
    indata = dchar + FrmoCharacterToCode([0, 0, 0, 0])

    outdata = int(hashlib.sha1(indata.encode()).hexdigest(), 16)

    for i in range(1, c1 + 1):
        indata = dchar + FrmoCharacterToCode([0, 0, 0, i])
        indata = int(hashlib.sha1(indata.encode()).hexdigest(), 16)
        outdata = outdata * pow(2, 160) + indata
    outdata = outdata >> int((c1 + 1) * 160 - dLen * 8)
    return hex(outdata)[2: int(2 * dLen + 2)]


def RSAOAEPEnc(m, mLen, n, e, r):
    if mLen != len(m) // 2:
        return False
    k = int(math.ceil(size(n) / 8))
    k2 = mLen
    k0 = int(math.ceil(size(r) / 8))
    k1 = k - 2 * k0 - k2 - 2
    if k1 < 0:
        return False
    lhash = hashlib.sha1().hexdigest()

    hLen = len(lhash) / 2

    x01 = "01"
    x00 = "00"
    ps = []
    while len(ps) != 2 * k1:
        ps.append("0")
    ps = "".join(ps)

    pad = int(lhash + ps + x01 + m, 16)

    s10 = int(MGF(hex(r)[2: len(hex(r))], k0 + k1 + k2 + 1), 16) ^ pad
    print("L ", s10)
    s16 = hex(s10)[2: len(hex(s10))]
    t10 = int(MGF(s16, k0), 16) ^ r
    t16 = hex(t10)[2: len(hex(t10))]
    w16 = x00 + t16 + s16

    print("After padding:\t", w16)
    w10 = int(w16, 16)

    str = hex(RSAEnc(w10, n, e))
    return str[2: len(str)]


def RSAOAEPDec(c, mLen, n, d, r):
    k = int(math.ceil(size(n) // 8))
    k0 = int(math.ceil(size(r) // 8))
    k2 = mLen
    k1 = k - 2 * k0 - k2 - 2
    w10 = RSADec(int(c, 16), d, n)
    print("\nDecrypted (before unpadding):\t", hex(w10))

    s10 = (pow(2, 8 * (k0 + k1 + k2 + 1)) - 1) & w10
    t10 = (pow(2, 8 * k0) - 1) & (w10 >> 8 * (k0 + k1 + k2 + 1))
    rr = int(MGF(hex(s10)[2: len(hex(s10))], k0), 16) ^ t10
    if r != rr:
        return False
    pad10 = int(MGF(hex(rr)[2: len(hex(rr))], k0 + k1 + k2 + 1), 16) ^ s10
    pad = hex(pad10)[2: len(hex(pad10))]
    m = (pow(2, 8 * k2) - 1) & pad10
    lhash = (pow(2, 8 * k0) - 1) & pad10 >> 8 * (k1 + k2 + 1)
    if hex(lhash)[2: len(hex(lhash))] != hashlib.sha1().hexdigest():
        return False
    return hex(m)[2: len(hex(m))]


msg = "Hello"
if (len(sys.argv) > 1):
    msg = str(sys.argv[1])
msg = msg[:16]
print("Message:\t", msg)

e = int("010001", 16)
n = int(
    "A9A4AFE96AF0B4F539B85FAD5F30D0B6C5394B73F672CB4BEF82A3D27349757DC33E925FECB0FCA4CC2219D90C4B8AA98CF5719BA79EB0AFEDA0FA6D42EEBA4F69562E6FF7015185B827FBAD264EBBC40984BD16273BDDB776E11169567BD3645D1A26656634A732F126B5E9044A5C88B9F6095AC874B0EA947BB35F48EBA4E7",
    16)
d = int(
    "67A981F1016F0B34DA4B86F39B3A6A1F754EF88368F266B6052A704ED631EA40AA411F12CCC0ADF149E800A177F8E5478C222384F91D685C68B9B8AD717C0D8E2037B8582241F50FB893531396192A41F1643EEACABD5803CB74AE2D6CB38FE7A226CC5B0724DF0D0B4A50E592C7E25D7BA6A9A19CF940EE49715F1CEA2AD6A1",
    16)
r = 788255724614721016190591162463944054696650907899

m = msg.encode().hex()

mLen = len(m) // 2

enc = RSAOAEPEnc(m, mLen, n, e, r)

print("\nEncrypted:\t", enc)
m = RSAOAEPDec(enc, mLen, n, d, r)

print("\nDecrypted:\t", binascii.unhexlify(m).decode())
print("\n---Parameters used---")
k = int(math.ceil(size(n) // 8))
k0 = int(math.ceil(size(r) // 8))
k2 = mLen
k1 = k - 2 * k0 - k2 - 2
print("k=", k, end=' ')
print("k0=", k0, end=' ')
print("k1=", k1, end=' ')
print("k2=", k2, end=' ')
print("mLen=", mLen)

print("\n---RSA Param---")
print("n=\t", n)
print("e=\t", e)
print("d=\t", d)
