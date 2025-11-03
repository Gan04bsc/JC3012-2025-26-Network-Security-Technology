# -*- coding: utf-8 -*-
"""
rsa_defense.py
按"增大模数 + 强素数"两大防线实现的 RSA 防御代码：
- 防御措施 1：使用足够大的模数（>= 2048 位）
- 防御措施 2：生成强素数（Gordon 算法，确保 p-1 与 p+1 各含大素因子）
- 使用 CSPRNG 生成随机数，Miller-Rabin 概率素性测试
- 默认 e = 65537，验证 gcd(e, p-1)=gcd(e, q-1)=1

可直接与您的 rsa_template.py 配合使用：
- 方案 A：用 defensive_generate_keys(bits=2048) 直接生成密钥对
- 方案 B：在用户给出 p,q,e 时，调用 validate_user_primes(...) 检查并拒绝弱参数
"""

from __future__ import annotations
from typing import Tuple, Optional
import secrets
import math

# -------- 基础数论工具 --------

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"不存在逆元：gcd({a}, {m}) = {g}")
    return x % m

def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus == 1:
        return 0
    result = 1
    base %= modulus
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result

# -------- Miller-Rabin 概率素性测试（含小素数试除） --------

_SMALL_PRIMES = [
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,
    53,59,61,67,71,73,79,83,89,97,101,103,107,109,113
]

def _trial_division(n: int) -> bool:
    # 返回 True 表示 n 可能是素数（未被小素数整除）
    if n < 2:
        return False
    # 2 单独处理
    if n % 2 == 0:
        return n == 2
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True

def _decompose(n: int) -> Tuple[int, int]:
    # 将 n-1 写成 2^s * d，返回 (s, d)
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d

def is_probable_prime(n: int, rounds: int = 64) -> bool:
    if n in (2, 3):
        return True
    if n % 2 == 0 or n < 2:
        return False
    if not _trial_division(n):
        return False
    # Miller-Rabin
    s, d = _decompose(n)
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

# -------- 随机数与候选生成 --------

def _random_odd(bits: int) -> int:
    # 最高位与最低位设为 1，确保位长与奇性
    n = secrets.randbits(bits)
    n |= (1 << (bits - 1))  # top bit
    n |= 1                  # odd
    return n

def generate_prime(bits: int) -> int:
    assert bits >= 2
    while True:
        cand = _random_odd(bits)
        if is_probable_prime(cand):
            return cand

def generate_safe_prime(bits: int) -> int:
    """
    生成 safe prime: p = 2*q + 1，q 为素数。
    注意：p 的位数约等于 bits（q ~ bits-1 位）
    """
    assert bits >= 3
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_probable_prime(p):
            return p

# -------- Gordon 风格的强素数生成 --------
def generate_strong_prime(bits: int) -> int:
    """
    生成“强素数” p，满足：
      - 存在大素数 r 使 r | (p - 1)
      - 存在大素数 s 使 s | (p + 1)
    实现思路（近似 Gordon 算法）：
      1) 取大素数 r（此处用 safe prime 以确保 r-1 含大素因子）
      2) 取大素数 s（同理）
      3) 构造 p0 = 2*r*x + 1 为素数，从而 r | p0-1
      4) 令 p = p0 + 2*r*t，使得 p ≡ -1 (mod s)，从而 s | p+1
      5) 如 p 非素数，则 p += k*(2*r*s) 继续寻素
    """
    assert bits >= 512, "强素数通常用于大模数；位数太小无现实意义"

    # r, s 规模取 ~ bits/2
    r_bits = bits // 2
    s_bits = bits // 2

    r = generate_safe_prime(r_bits)
    s = generate_safe_prime(s_bits)

    # Step 3: 找到 p0 = 2*r*x + 1 为素数，且位数达到目标
    while True:
        # x 选择使 p0 约为目标位数
        x_bits = max(2, bits - (r.bit_length() + 1))
        x = _random_odd(x_bits)
        p0 = 2 * r * x + 1
        if p0.bit_length() < bits:
            # 不足指定位长，扩大 x
            continue
        if is_probable_prime(p0):
            break

    # Step 4: 选 t 使 p ≡ -1 (mod s)
    inv = modinv((2 * r) % s, s)
    t = ((-p0 - 1) * inv) % s
    p = p0 + 2 * r * t

    # 确保位数足够；不足则加整步长 2*r*s
    step = 2 * r * s
    while p.bit_length() < bits:
        p += step

    # Step 5: 尝试 p, p + k*step... 直到为素数
    while not is_probable_prime(p):
        p += step

    return p

# -------- RSA 强化密钥生成与验证 --------

DEFAULT_E = 65537
MIN_KEY_BITS = 2048

def _gen_strong_distinct_primes_each(bits_half: int, e: int) -> Tuple[int, int]:
    """生成两个不同的强素数，确保与 e 互斥（p-1、q-1 与 e 互质）。"""
    while True:
        p = generate_strong_prime(bits_half)
        if gcd(e, p - 1) != 1:
            continue
        # q 循环直到满足所有条件
        while True:
            q = generate_strong_prime(bits_half)
            if p == q:
                continue
            if gcd(e, q - 1) != 1:
                continue
            break
        return p, q

def defensive_generate_keys(bits: int = 2048, e: int = DEFAULT_E) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    生成强化版 RSA 密钥对：
      - 位长 >= 2048
      - e 默认为 65537
      - p, q 使用强素数生成，并保证 gcd(e, p-1)=gcd(e, q-1)=1
      - 返回：((n, e), (n, d), (p, q))
    """
    if bits < MIN_KEY_BITS:
        raise ValueError(f"密钥位数过小：{bits}，请至少使用 {MIN_KEY_BITS} 位。")
    if e < 3 or e % 2 == 0:
        raise ValueError("e 必须为奇数且 >= 3；推荐 e=65537。")

    half = bits // 2
    p, q = _gen_strong_distinct_primes_each(half, e)
    n = p * q
    # 使用 φ(n)（也可用 lcm(p-1, q-1)）
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        # 理论上不该发生（已确保与 p-1/q-1 互质）
        raise RuntimeError("e 与 φ(n) 不互质，请重试。")
    d = modinv(e, phi)
    return (n, e), (n, d), (p, q)

# -------- 输入校验（若继续让用户自填 p, q, e） --------

def validate_user_primes(p: int, q: int, e: int, min_bits: int = MIN_KEY_BITS) -> None:
    """
    在您现有的交互式流程中调用，用于拒绝弱参数：
      - p, q 为素数（概率测试）
      - 位数达到要求
      - p != q
      - gcd(e, p-1)=gcd(e, q-1)=1
    """
    if p <= 1 or q <= 1 or p == q:
        raise ValueError("p 与 q 必须为不同的素数且 > 1。")

    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p 或 q 未通过素性测试。")

    n_bits = (p * q).bit_length()
    if n_bits < min_bits:
        raise ValueError(f"模数位数过小（{n_bits} 位），请至少使用 {min_bits} 位。")

    if e < 3 or e % 2 == 0:
        raise ValueError("e 必须为奇数且 >= 3；推荐 e=65537。")

    if gcd(e, (p - 1)) != 1 or gcd(e, (q - 1)) != 1:
        raise ValueError("e 与 (p-1) 或 (q-1) 不互质，建议更换 p/q 或使用 e=65537。")


# -------- 与 RSA_python.py 联动的安全密钥生成 --------

def secure_generate_keys(p: int, q: int, e: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    联动 RSA_python.py 的密钥生成流程，但增加安全验证：
    - 先调用 validate_user_primes 检查参数安全性
    - 如果通过验证，则生成密钥对
    返回：((n, e), (n, d))
    """
    # 严格验证用户输入的参数
    validate_user_primes(p, q, e)
    
    # 验证通过后，生成密钥对
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return (n, e), (n, d)

# -------- 加解密函数（与 RSA_python.py 保持一致） --------

def encrypt(m: int, pubkey: Tuple[int, int]) -> int:
    """RSA 加密：c = m^e mod n"""
    n, e = pubkey
    if not (0 <= m < n):
        raise ValueError(f"明文 m 必须满足 0 <= m < n (n={n})")
    return modexp(m, e, n)

def decrypt(c: int, privkey: Tuple[int, int]) -> int:
    """RSA 解密：m = c^d mod n"""
    n, d = privkey
    if not (0 <= c < n):
        raise ValueError(f"密文 c 必须满足 0 <= c < n (n={n})")
    return modexp(c, d, n)

# -------- 便捷示例 --------

def demo_hardened_key(bits: int = 2048, e: int = DEFAULT_E):
    """演示自动生成强化密钥对"""
    print(f"\n{'='*60}")
    print("方案 A：自动生成强化密钥对")
    print(f"{'='*60}")
    print(f"参数：密钥位数 = {bits}，e = {e}")
    print("正在生成强素数 p, q...")
    print("（这可能需要几秒钟到几十秒，请耐心等待）\n")
    
    pub, priv, pq = defensive_generate_keys(bits=bits, e=e)
    (n, e_out), (n2, d), (p, q) = pub, priv, pq
    assert n == n2
    
    print(f"✅ 生成成功！")
    print(f"\n密钥参数：")
    print(f"  n 位数 = {n.bit_length()} 位")
    print(f"  p 位数 = {p.bit_length()} 位")
    print(f"  q 位数 = {q.bit_length()} 位")
    print(f"  e = {e_out}")
    print(f"  d 位数 = {d.bit_length()} 位")
    print(f"\n公钥 (e, n):")
    print(f"  e = {e_out}")
    print(f"  n = {n}")
    print(f"\n私钥 (d, n):")
    print(f"  d = {d}")
    print(f"  n = {n}")
    
    # 加解密往返测试
    print(f"\n{'='*60}")
    print("加解密测试")
    print(f"{'='*60}")
    m = 123456789
    print(f"原始明文 M = {m}")
    c = encrypt(m, (n, e_out))
    print(f"加密后密文 C = {c}")
    m2 = decrypt(c, (n, d))
    print(f"解密后明文 M' = {m2}")
    print(f"验证结果：{'OK ✅' if m == m2 else '失败 ❌'}")
    
    return pub, priv, pq

def demo_user_input_with_validation():
    """演示用户输入参数并进行安全验证"""
    print(f"\n{'='*60}")
    print("方案 B：用户输入参数并进行安全验证")
    print(f"{'='*60}")
    print("\n⚠️  安全要求：")
    print(f"  1. p 和 q 必须是大素数（至少 1024 位以上）")
    print(f"  2. 模数 n = p * q 至少 {MIN_KEY_BITS} 位")
    print(f"  3. p 和 q 不能相同且不能太接近")
    print(f"  4. e 必须与 (p-1) 和 (q-1) 互质")
    print(f"  5. 推荐使用 e = 65537\n")
    
    try:
        p_str = input("请输入素数 p: ").strip()
        q_str = input("请输入素数 q: ").strip()
        e_str = input("请输入公钥指数 e (推荐 65537): ").strip()
        
        p = int(p_str)
        q = int(q_str)
        e = int(e_str) if e_str else DEFAULT_E
        
        print(f"\n正在验证参数安全性...")
        print(f"  - 检查 p, q 是否为素数...")
        print(f"  - 检查密钥位数是否满足最低要求 ({MIN_KEY_BITS} 位)...")
        print(f"  - 检查 e 与 (p-1), (q-1) 的互质性...")
        
        # 调用验证函数（这里会抛出异常如果不满足要求）
        pub, priv = secure_generate_keys(p, q, e)
        (n, e_out), (n2, d) = pub, priv
        
        print(f"\n✅ 验证通过！参数满足安全要求。")
        print(f"\n生成的密钥对：")
        print(f"公钥 (e, n):")
        print(f"  e = {e_out}")
        print(f"  n = {n}")
        print(f"\n私钥 (d, n):")
        print(f"  d = {d}")
        print(f"  n = {n2}")
        
        # 加解密测试
        print(f"\n{'='*60}")
        print("加解密测试")
        print(f"{'='*60}")
        M_str = input("\n请输入明文 M (0 <= M < n): ").strip()
        M = int(M_str)
        
        C = encrypt(M, pub)
        print(f"\n加密后的密文 C = {C}")
        
        M2 = decrypt(C, priv)
        print(f"解密后的明文 M' = {M2}")
        print(f"\n验证：加解密是否一致：{'OK ✅' if M == M2 else '不一致 ❌'}")
        
        return pub, priv
        
    except ValueError as e:
        print(f"\n❌ 参数验证失败：{e}")
        print(f"\n说明：")
        print(f"  您输入的参数不满足安全要求。")
        print(f"  建议使用方案 A 自动生成强化密钥对，或重新输入符合要求的参数。")
        return None, None
    except Exception as e:
        print(f"\n❌ 发生错误：{e}")
        return None, None

def compare_weak_vs_strong():
    """对比演示：弱参数 vs 强参数"""
    print(f"\n{'='*60}")
    print("安全对比演示：弱参数 vs 强参数")
    print(f"{'='*60}")
    
    print("\n【场景 1】尝试使用弱参数（小素数）")
    print("-" * 60)
    # 使用小素数（会被拒绝）
    p_weak = 61
    q_weak = 53
    e_weak = 17
    print(f"参数：p = {p_weak}, q = {q_weak}, e = {e_weak}")
    print(f"模数 n = {p_weak * q_weak} (位数: {(p_weak * q_weak).bit_length()})")
    
    try:
        validate_user_primes(p_weak, q_weak, e_weak)
        print("✅ 验证通过")
    except ValueError as ex:
        print(f"❌ 验证失败：{ex}")
    
    print("\n【场景 2】尝试使用相同的素数")
    print("-" * 60)
    p_same = generate_prime(1024)
    print(f"参数：p = q = {p_same} (位数: {p_same.bit_length()})")
    
    try:
        validate_user_primes(p_same, p_same, DEFAULT_E)
        print("✅ 验证通过")
    except ValueError as ex:
        print(f"❌ 验证失败：{ex}")
    
    print("\n【场景 3】使用安全的参数")
    print("-" * 60)
    print("正在生成两个 1024 位的强素数...")
    p_good = generate_strong_prime(1024)
    q_good = generate_strong_prime(1024)
    
    # 确保 p != q
    while p_good == q_good:
        q_good = generate_strong_prime(1024)
    
    print(f"✅ 生成完成")
    print(f"模数位数: {(p_good * q_good).bit_length()}")
    
    try:
        validate_user_primes(p_good, q_good, DEFAULT_E)
        print("✅ 验证通过：参数满足所有安全要求")
    except ValueError as ex:
        print(f"❌ 验证失败：{ex}")

def validate_defense_1(p: int, q: int, e: int) -> None:
    """
    防御措施 1：验证模数大小
    只检查密钥位数是否 >= 2048 位
    """
    if p <= 1 or q <= 1 or p == q:
        raise ValueError("p 与 q 必须为不同的素数且 > 1。")
    
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p 或 q 未通过素性测试。")
    
    n_bits = (p * q).bit_length()
    if n_bits < MIN_KEY_BITS:
        raise ValueError(f"模数位数过小（{n_bits} 位），必须 >= {MIN_KEY_BITS} 位。")
    
    if e < 3 or e % 2 == 0:
        raise ValueError("e 必须为奇数且 >= 3；推荐 e=65537。")
    
    if gcd(e, (p - 1)) != 1 or gcd(e, (q - 1)) != 1:
        raise ValueError("e 与 (p-1) 或 (q-1) 不互质，建议使用 e=65537。")

def validate_defense_2(p: int, q: int, e: int) -> None:
    """
    防御措施 2：验证强素数
    检查 p-1 和 p+1 是否含有大素因子
    """
    # 首先进行基本验证
    validate_defense_1(p, q, e)
    
    # 检查是否为强素数
    if not is_strong_prime_check(p):
        raise ValueError("p 不是强素数（p-1 或 p+1 不含有足够大的素因子）。")
    
    if not is_strong_prime_check(q):
        raise ValueError("q 不是强素数（q-1 或 q+1 不含有足够大的素因子）。")

def is_strong_prime_check(p: int) -> bool:
    """
    检查 p 是否为强素数
    验证 p-1 和 p+1 是否含有大素因子
    """
    if not is_probable_prime(p):
        return False
    
    # 检查 p-1 是否有大素因子（不能被小素数完全分解）
    pm1 = p - 1
    for small in _SMALL_PRIMES:
        while pm1 % small == 0:
            pm1 //= small
    
    # 如果剩余部分太小，说明 p-1 只有小素因子
    if pm1.bit_length() < p.bit_length() // 3:
        return False
    
    # 检查 p+1 是否有大素因子
    pp1 = p + 1
    for small in _SMALL_PRIMES:
        while pp1 % small == 0:
            pp1 //= small
    
    # 如果剩余部分太小，说明 p+1 只有小素因子
    if pp1.bit_length() < p.bit_length() // 3:
        return False
    
    return True

def print_defense_summary():
    """打印防御措施总结"""
    print(f"\n{'='*60}")
    print("RSA 防御措施总结")
    print(f"{'='*60}")
    print("""
本代码实现了以下针对 RSA 攻击的防御措施：

【防御措施 1】使用足够大的模数（n）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• 强制要求：密钥位数 >= 2048 位
• 原理：Pollard's rho 算法复杂度为 O(√p)
  当密钥长度加倍时，攻击难度呈指数级上升
• 实践标准：
  - 一般系统：2048 位（最低安全标准）
  - 高安全系统：3072 位或 4096 位
  - 本代码默认：2048 位

【防御措施 2】生成强素数（Strong Primes）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• 强素数条件：
  ✓ p 是大素数
  ✓ p-1 含有大素因子 r（抵抗 Pollard's p-1 攻击）
  ✓ p+1 含有大素因子 s（抵抗 Williams' p+1 攻击）
  ✓ r-1 也含有大素因子（增强安全层次）

• 生成方法：
  ✓ 使用 CSPRNG（密码学安全伪随机数生成器）
  ✓ Miller-Rabin 概率素性测试（64 轮）
  ✓ Gordon 算法风格的强素数构造
  ✓ 确保 gcd(e, p-1) = gcd(e, q-1) = 1

【参数验证】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• validate_user_primes() 函数用于验证用户输入参数：
  ✓ p, q 必须为不同的素数
  ✓ 模数 n 位数必须 >= 2048 位
  ✓ e 必须与 (p-1) 和 (q-1) 互质
  ✓ e 必须为奇数且 >= 3（推荐 65537）

【使用方式】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
方案 A：自动生成强化密钥对
  pub, priv, pq = defensive_generate_keys(bits=2048)

方案 B：验证用户输入的参数
  validate_user_primes(p, q, e)  # 如果不安全会抛出异常
  pub, priv = secure_generate_keys(p, q, e)

【对抗的主要攻击方法】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• 防御措施 1（大模数）主要对抗：
  ✓ Pollard's rho 因式分解（时间复杂度 O(√p)）
  ✓ 其他因式分解算法（如数域筛法 NFS）
  
• 防御措施 2（强素数）主要对抗：
  ✓ Pollard's p-1 算法（需要 p-1 含大素因子）
  ✓ Williams' p+1 算法（需要 p+1 含大素因子）
  ✓ 特殊结构素数的快速分解方法
    """)

def interactive_menu():
    """简化的交互式菜单"""
    print(f"\n{'='*60}")
    print("RSA 安全防御系统")
    print(f"{'='*60}")
    print("请选择防御方法：")
    print("  1. 防御措施 1：使用足够大的模数（>= 2048 位）")
    print("  2. 防御措施 2：生成强素数（Gordon 算法）")
    print("-" * 60)
    
    choice = input("请输入选项 (1 或 2): ").strip()
    
    if choice not in ["1", "2"]:
        print("\n❌ 无效选项，程序退出。")
        return
    
    defense_mode = int(choice)
    
    while True:
        print(f"\n{'='*60}")
        if defense_mode == 1:
            print("防御措施 1：使用足够大的模数")
            print("要求：密钥位数必须 >= 2048 位")
        else:
            print("防御措施 2：生成强素数")
            print("要求：p-1 和 p+1 都含有大素因子")
        print(f"{'='*60}")
        
        try:
            p_str = input("请输入素数 p: ").strip()
            q_str = input("请输入素数 q: ").strip()
            e_str = input(f"请输入公钥指数 e (留空默认 {DEFAULT_E}): ").strip()
            
            p = int(p_str)
            q = int(q_str)
            e = int(e_str) if e_str else DEFAULT_E
            
            print(f"\n正在验证参数...")
            
            # 根据选择的防御方法进行不同的验证
            if defense_mode == 1:
                validate_defense_1(p, q, e)
            else:
                validate_defense_2(p, q, e)
            
            # 验证通过，生成密钥
            pub, priv = secure_generate_keys(p, q, e)
            (n, e_out), (n2, d) = pub, priv
            
            print(f"\n✅ 参数验证通过！")
            print(f"\n密钥生成成功：")
            print(f"  模数 n: {n}")
            print(f"  位数: {n.bit_length()} 位")
            print(f"  公钥 e: {e_out}")
            print(f"  私钥 d: {d}")
            print(f"  素数 p: {p}")
            print(f"  素数 q: {q}")
            break
            
        except ValueError as ex:
            print(f"\n❌ 参数验证失败：{ex}")
            print(f"\n{'='*60}")
            print("建议：")
            if defense_mode == 1:
                print("  - 使用更大的素数 p 和 q（各自至少 1024 位）")
                print("  - 确保 p * q >= 2048 位")
                print("  - 确保 p 和 q 是不同的素数")
                print("  - 推荐使用 e = 65537")
                print("\n示例参数（供参考）：")
                print("  p: 使用 1024 位的大素数")
                print("  q: 使用另一个 1024 位的大素数")
                print("  e: 65537")
            else:
                print("  - 使用强素数（p-1 和 p+1 都含有大素因子）")
                print("  - 建议使用专门工具生成强素数")
                print("  - 确保 p 和 q 都是强素数")
                print("  - 推荐使用 e = 65537")
                print("\n强素数特征：")
                print("  ✓ p-1 含有大素因子 r（抵抗 Pollard's p-1）")
                print("  ✓ p+1 含有大素因子 s（抵抗 Williams' p+1）")
            print(f"{'='*60}")
            
            print("\n请选择：")
            print("  1. 重新手动输入参数")
            print("  2. 自动生成符合要求的参数（推荐）")
            print("  3. 退出程序")
            
            retry = input("\n请输入选项 (1/2/3): ").strip()
            
            if retry == '1':
                continue  # 继续循环，重新输入
            elif retry == '2':
                # 自动生成符合要求的参数
                print(f"\n{'='*60}")
                print("正在自动生成参数...")
                print(f"{'='*60}")
                
                try:
                    if defense_mode == 1:
                        # 防御措施1：生成大素数
                        bits_input = input(f"\n请输入密钥位数（默认 {MIN_KEY_BITS}，推荐 2048/3072/4096）: ").strip()
                        bits = int(bits_input) if bits_input else MIN_KEY_BITS
                        
                        print(f"\n⏳ 正在生成 {bits} 位密钥...")
                        print("   这可能需要几秒到几分钟，请耐心等待...\n")
                        
                        p = generate_safe_prime(bits // 2)
                        print(f"✓ 生成素数 p ({p.bit_length()} 位)")
                        
                        q = generate_safe_prime(bits // 2)
                        print(f"✓ 生成素数 q ({q.bit_length()} 位)")
                        
                        e = DEFAULT_E
                        
                    else:
                        # 防御措施2：生成强素数
                        bits_input = input(f"\n请输入密钥位数（默认 {MIN_KEY_BITS}，推荐 2048/3072/4096）: ").strip()
                        bits = int(bits_input) if bits_input else MIN_KEY_BITS
                        
                        print(f"\n⏳ 正在生成 {bits} 位强素数密钥（Gordon 算法）...")
                        print("   这可能需要较长时间，请耐心等待...\n")
                        
                        p = generate_strong_prime(bits // 2)
                        print(f"✓ 生成强素数 p ({p.bit_length()} 位)")
                        
                        q = generate_strong_prime(bits // 2)
                        print(f"✓ 生成强素数 q ({q.bit_length()} 位)")
                        
                        e = DEFAULT_E
                    
                    # 验证生成的参数
                    if defense_mode == 1:
                        validate_defense_1(p, q, e)
                    else:
                        validate_defense_2(p, q, e)
                    
                    # 生成密钥
                    pub, priv = secure_generate_keys(p, q, e)
                    (n, e_out), (n2, d) = pub, priv
                    
                    print(f"\n✅ 密钥生成成功！")
                    print(f"\n{'='*60}")
                    print("生成的密钥参数：")
                    print(f"{'='*60}")
                    print(f"  模数 n: {n}")
                    print(f"  位数: {n.bit_length()} 位")
                    print(f"  公钥 e: {e_out}")
                    print(f"  私钥 d: {d}")
                    print(f"\n  素数 p: {p}")
                    print(f"  素数 q: {q}")
                    print(f"{'='*60}")
                    break
                    
                except Exception as gen_ex:
                    print(f"\n❌ 自动生成失败：{gen_ex}")
                    print("程序退出。")
                    break
            else:
                print("\n程序退出。")
                break

if __name__ == "__main__":
    interactive_menu()
