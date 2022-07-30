import math
import random
from gmssl import sm3,func

#模余运算 a mod b
def amodb(a,b):
    if math.isinf(a):
        return float('inf')
    else:
        return a % b

#判断二次剩余
def Legend(n,p):
    return pow(n,(p-1)//2,p)

#椭圆曲线上的点加
def pointadd(P,Q,a,p):
    if (math.isinf(P[0]) or math.isinf(P[1])) and (~math.isinf(Q[0]) and ~math.isinf(Q[1])):  
        Z = Q
    elif (~math.isinf(P[0]) and ~math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])): 
        Z = P
    elif (math.isinf(P[0]) or math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):  
        Z = [float('inf'), float('inf')]
    else:
        if P != Q:
            l = modmul(Q[1] - P[1], Q[0] - P[0], p)
        else:
            l = modmul(3 * P[0] ** 2 + a, 2 * P[1], p)
        a = amodb(l ** 2 - P[0] - Q[0], p)
        b = amodb(l * (P[0] - a) - P[1], p)
        Z = [a, b]
    return Z

#椭圆曲线上点与正整数乘
def npointmul(k,P,a,p):
    k1=bin(k)[2:]
    lens=len(k1)-1
    R=P
    if lens>0:
        k=k-2**lens
        while lens>0:
            R=pointadd(R,R,a,p)
            lens-=1
        if k>0:
            R=pointadd(R,npointmul(k,P,a,p),a,p)
    return R

#返回值x=a*b^(-1) mod n
def modmul(a,b,n):
    if b == 0:
        res = float('inf')
    elif a == 0:
        res = 0
    else:
        t = bin(n - 2)[2:]
        y = 1
        i = 0
        while i < len(t):  
            y = (y ** 2) % n 
            if t[i] == '1':
                y = (y * b) % n
            i += 1
        res = (y * a) % n
    return res

#SM2密钥对生成函数
def keygenera(a,p,n,G):
    pri = random.randint(1, n - 2)
    pub = npointmul(pri, G, a, p)
    return pri,pub

#求解二次剩余
def QR(n,p):
    assert Legend(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q = q // 2
        s += 1
    for z in range(2, p):
        if Legend(z, p) == p - 1:
            c = pow(z, q, p)
            break
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1:
            temp = pow(t, 2 ** (i + 1), p)
            i += 1
            if temp % p == 1:
                b = pow(c, 2 ** (m - i - 1), p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0
        return r

#Hash
def hash0(mess):
    res=[float("inf"), float("inf")]
    for i in mess:
        x = int(sm3.sm3_hash(func.bytes_to_list(i)), 16)
        tmp = amodb(x ** 2 + a * x + b, p)
        y = QR(tmp, p)
        res = pointadd(res, [x, y], a, p)
    return res

if __name__ == '__main__':
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    G = [Gx, Gy]
    [sk, pk] = keygenera(a, p, n, G)
    print("私钥:\n",sk)
    print("公钥:\n",pk)
    s=(b'12345',b'114514')
    print("piont=",s)
    res=hash0(s)
    print("Hash:\n",res)
