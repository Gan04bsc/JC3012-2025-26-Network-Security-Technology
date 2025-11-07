# === 攻击：对 RSA 的因式分解（Pollard's rho + Pollard's p-1）恢复 d 并解密 ===
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

def pollards_p_minus_1(n: int, B1: int = 1_000_000, B2: int = 10_000_000) -> int | None:
    """
    Pollard's p-1 算法：当 n 的某个因子 p 满足 p-1 是 B-smooth 时有效
    
    原理：
    - 如果 p-1 的所有素因子都 ≤ B1，则称 p-1 是 B1-smooth
    - 计算 a = 2^(B1!) mod n，则 a^(p-1) ≡ 1 (mod p)
    - gcd(a-1, n) 可能得到因子 p
    
    参数：
    - n: 待分解的合数
    - B1: 第一阶段界限（主要计算）
    - B2: 第二阶段界限（可选，用于处理 p-1 有一个稍大素因子的情况）
    
    返回：
    - 找到的非平凡因子，或 None（失败）
    """
    if n % 2 == 0:
        return 2
    
    # 第一阶段：计算 a = 2^(B1!) mod n
    # 实际上不计算 B1!，而是累乘所有 ≤ B1 的素数幂
    a = 2
    
    # 生成 ≤ B1 的所有素数（简单的埃拉托斯特尼筛法）
    def sieve_primes(limit):
        if limit < 2:
            return []
        is_prime = [True] * (limit + 1)
        is_prime[0] = is_prime[1] = False
        for i in range(2, int(limit**0.5) + 1):
            if is_prime[i]:
                for j in range(i*i, limit + 1, i):
                    is_prime[j] = False
        return [i for i in range(2, limit + 1) if is_prime[i]]
    
    primes = sieve_primes(B1)
    
    # 对每个素数 q，计算 q^k 使得 q^k ≤ B1 < q^(k+1)
    for q in primes:
        q_power = q
        while q_power <= B1:
            a = pow(a, q, n)
            q_power *= q
    
    # 检查 gcd(a-1, n)
    g = gcd(a - 1, n)
    if 1 < g < n:
        return g
    
    # 第一阶段失败，尝试第二阶段（可选）
    # 这里简化实现：只检查一些额外的素数
    if B2 > B1:
        # 继续用 B1 到 B2 之间的素数
        primes_B2 = [p for p in sieve_primes(B2) if p > B1]
        for q in primes_B2[:100]:  # 限制数量，避免太慢
            a = pow(a, q, n)
            g = gcd(a - 1, n)
            if 1 < g < n:
                return g
    
    return None

def attack_and_decrypt(n: int, e: int, C: int | None = None, method: str = 'rho'):
    """
    攻击入口：给定 (n, e)，返回 p, q, d；若提供密文 C，则一并还原明文 M。
    
    参数：
    - method: 'rho' 使用 Pollard's rho，'p-1' 使用 Pollard's p-1
    """
    if method == 'rho':
        p, q, d = recover_private_key(n, e)
    elif method == 'p-1':
        factor = pollards_p_minus_1(n)
        if factor is None or factor == 1 or factor == n:
            raise RuntimeError("Pollard's p-1 攻击失败")
        p = factor
        q = n // factor
        if p > q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)
    else:
        raise ValueError(f"未知攻击方法: {method}")
    
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
