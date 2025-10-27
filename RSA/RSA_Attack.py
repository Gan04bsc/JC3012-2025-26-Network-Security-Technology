# === 攻击：对 RSA 的因式分解（Pollard's rho）恢复 d 并解密 ===
# 适用：教学/实验。仅对小/弱模数有效；2048 位以上实际不可行。

import random
from RSA_python import modinv, modexp
from math import gcd  

def _small_factor(n: int, bound: int = 100_000):
    """快速试除，先捡小因子，加速失败重启次数。"""
    if n % 2 == 0:
        return 2
    f = 3
    # 只到给定上界，避免在大数上卡太久
    limit = min(bound, int(n**0.5) + 1)
    while f <= limit:
        if n % f == 0:
            return f
        f += 2
    return None

def pollards_rho(n: int, max_steps: int = 200_000, max_tries: int = 30) -> int | None:
    """
    经典 Floyd 快慢指针版 rho。
    返回一个非平凡因子 d（1<d<n），失败则返回 None。
    """
    if n % 2 == 0:
        return 2
    # 先试一下小因子，省时间
    sf = _small_factor(n)
    if sf:
        return sf

    for _ in range(max_tries):
        # 随机选择参数与起点，失败则重启
        c = random.randrange(1, n - 1)
        x = random.randrange(2, n - 2)
        y = x
        d = 1
        for _ in range(max_steps):
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
            if d == 1:
                continue
            if d == n:
                # 本次参数糟糕，跳出重启
                break
            return d
        # 本轮失败，进行下一次重启
    return None

def factor_semiprime(n: int) -> tuple[int, int]:
    """对二素数模数 n 求 p, q。"""
    d = pollards_rho(n)
    if d is None or d == 1 or d == n:
        raise RuntimeError("分解失败：可能 n 过大或需提高迭代/重启次数。")
    p = d
    q = n // d
    if p * q != n:
        raise AssertionError("分解结果不一致。")
    # 规范化：p < q
    if p > q:
        p, q = q, p
    return p, q

def recover_private_key(n: int, e: int) -> tuple[int, int, int]:
    """通过分解 n 恢复 (p, q, d)。"""
    p, q = factor_semiprime(n)
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return p, q, d

def attack_and_decrypt(n: int, e: int, C: int | None = None):
    """
    攻击入口：给定 (n, e)，返回 p, q, d；若提供密文 C，则一并还原明文 M。
    """
    p, q, d = recover_private_key(n, e)
    result = {"p": p, "q": q, "d": d}
    if C is not None:
        result["M"] = modexp(C, d, n)
    return result

if __name__ == "__main__":
    print("=== RSA 攻击演示（Pollard's rho）===")
    n = int(input("请输入 n: "))
    e = int(input("请输入 e: "))
    c_in = input("可选：输入密文 C（留空跳过解密）: ").strip()
    C = int(c_in) if c_in else None
    out = attack_and_decrypt(n, e, C)
    print(f"分解得到：p={out['p']}, q={out['q']}")
    print(f"恢复私钥 d={out['d']}")
    if 'M' in out:
        print(f"解密得到明文 M={out['M']}")
