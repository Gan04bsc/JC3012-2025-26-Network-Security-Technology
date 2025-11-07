# -*- coding: utf-8 -*-
"""
experiment_2_defense.py
实验二：展示防御措施的有效性

对比实验：
1. weak_smooth vs safe_prime（针对 Pollard's p-1 攻击）
   - weak_smooth: p-1 是 B-smooth（所有素因子 ≤ B）
   - safe_prime: p = 2q+1（q 是大素数）

关键指标：
- ASR (Attack Success Rate): 攻击成功率
- 对比防御前后的 ASR 变化
"""

import time
import json
import secrets
from typing import Tuple, Optional, Dict, List
from datetime import datetime
from RSA_python import modexp, modinv, gcd
from RSA_Attack import pollards_p_minus_1

# ============ 素性测试 ============

def _trial_division_simple(n: int) -> bool:
    """简单的试除法素性测试"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True

def _miller_rabin_simple(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin 素性测试"""
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
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

def is_probable_prime(n: int) -> bool:
    """组合素性测试"""
    if not _trial_division_simple(n):
        return False
    return _miller_rabin_simple(n)

# ============ 普通素数生成 ============

def generate_prime_simple(bits: int) -> int:
    """生成指定位数的普通素数"""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        
        if is_probable_prime(candidate):
            return candidate

# ============ B-smooth 素数生成 ============

def is_b_smooth(n: int, B: int) -> bool:
    """检查 n 是否是 B-smooth（所有素因子 ≤ B）"""
    if n <= 1:
        return False
    
    temp = n
    # 试除所有 ≤ B 的小因子
    for d in range(2, min(B + 1, int(temp**0.5) + 1)):
        while temp % d == 0:
            temp //= d
        # 如果已经除尽，提前退出
        if temp == 1:
            return True
    
    # 检查剩余部分
    # 如果 temp > B，说明有大于 B 的素因子，不是 B-smooth
    # 如果 temp <= B，说明 temp 本身是 ≤ B 的素数，是 B-smooth
    return temp == 1 or temp <= B

def get_largest_prime_factor(n: int) -> int:
    """返回 n 的最大素因子（调试用）"""
    if n <= 1:
        return 0
    
    largest = 0
    temp = n
    
    # 试除小因子
    d = 2
    while d * d <= temp:
        while temp % d == 0:
            largest = d
            temp //= d
        d += 1
    
    # 剩余的就是最大素因子
    if temp > 1:
        largest = temp
    
    return largest

def generate_smooth_prime(bits: int, smoothness_bound: int = 10000) -> int:
    """
    生成一个素数 p，使得 p-1 是 B-smooth（B = smoothness_bound）
    """
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
    
    small_primes = sieve_primes(smoothness_bound)
    
    max_attempts = 1000
    for attempt in range(max_attempts):
        product = 1
        target_bits = bits - 1
        
        primes_used = []
        while product.bit_length() < target_bits:
            prime = small_primes[secrets.randbelow(len(small_primes))]
            product *= prime
            primes_used.append(prime)
        
        while product.bit_length() > target_bits and len(primes_used) > 1:
            product //= primes_used.pop()
        
        for k in range(1, 100):
            p = k * product + 1
            
            if p.bit_length() != bits:
                continue
            
            if is_probable_prime(p):
                if is_b_smooth(p - 1, smoothness_bound):
                    return p
    
    # 兜底：返回普通素数
    return generate_prime_simple(bits)

# ============ weak_smooth 密钥生成 ============

def generate_weak_smooth_keys(total_bits: int, smoothness_bound: int = 10000, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    生成弱 B-smooth 密钥：p-1 是 B-smooth，容易被 Pollard's p-1 攻击
    返回：((n, e), (n, d), (p, q))
    """
    half = total_bits // 2
    
    p = generate_smooth_prime(half, smoothness_bound)
    while gcd(e, (p - 1)) != 1:
        p = generate_smooth_prime(half, smoothness_bound)
    
    q = generate_smooth_prime(half, smoothness_bound)
    while gcd(e, (q - 1)) != 1 or p == q:
        q = generate_smooth_prime(half, smoothness_bound)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    
    return (n, e), (n, d), (p, q)

# ============ safe_prime 密钥生成（导入防御模块） ============

try:
    from RSA_Defense import generate_safe_prime
    DEFENSE_AVAILABLE = True
except ImportError:
    DEFENSE_AVAILABLE = False
    print("⚠️  警告：RSA_Defense 模块未找到，无法测试 safe_prime")

def generate_safe_prime_keys(total_bits: int, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    生成 safe_prime 密钥：p = 2q+1（q 是大素数）
    返回：((n, e), (n, d), (p, q))
    """
    if not DEFENSE_AVAILABLE:
        raise RuntimeError("RSA_Defense 模块不可用")
    
    half = total_bits // 2
    
    p = generate_safe_prime(half)
    while gcd(e, p - 1) != 1:
        p = generate_safe_prime(half)
    
    q = generate_safe_prime(half)
    while gcd(e, q - 1) != 1 or p == q:
        q = generate_safe_prime(half)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    
    return (n, e), (n, d), (p, q)

# ============ 攻击测试函数 ============

def test_pollards_p_minus_1(n: int, p_true: int, q_true: int, B1: int = 1_000_000, B2: int = 10_000_000) -> Dict:
    """
    对单个密钥执行 Pollard's p-1 攻击
    """
    result = {
        'success': False,
        'time_seconds': 0.0,
        'p_found': None,
        'q_found': None
    }
    
    start_time = time.time()
    
    try:
        factor = pollards_p_minus_1(n, B1=B1, B2=B2)
        
        if factor is not None and 1 < factor < n:
            p_found = factor
            q_found = n // factor
            
            if p_found > q_found:
                p_found, q_found = q_found, p_found
            
            if p_found * q_found == n:
                result['success'] = True
                result['p_found'] = p_found
                result['q_found'] = q_found
    
    except Exception as ex:
        result['error'] = str(ex)
    
    result['time_seconds'] = time.time() - start_time
    
    return result

# ============ 批量实验函数 ============

def run_experiment_batch(key_type: str, bits: int, num_trials: int, 
                        smoothness_bound: int = 10000,
                        B1: int = 1_000_000, B2: int = 10_000_000,
                        verbose: bool = True) -> Dict:
    """
    对指定配置进行批量测试
    """
    if verbose:
        print(f"\n{'='*70}")
        print(f"配置: {key_type} @ {bits}位 vs Pollard's p-1")
        print(f"{'='*70}")
    
    results = {
        'key_type': key_type,
        'bits': bits,
        'smoothness_bound': smoothness_bound if key_type == 'weak_smooth' else None,
        'B1': B1,
        'B2': B2,
        'num_trials': num_trials,
        'trials': [],
        'success_count': 0,
        'avg_time_all': 0.0,
        'avg_time_success': 0.0,
        'avg_time_failed': 0.0,
        'ASR': 0.0
    }
    
    total_time = 0.0
    success_time = 0.0
    failed_time = 0.0
    
    for trial_num in range(num_trials):
        if verbose:
            print(f"\n  试验 {trial_num + 1}/{num_trials}...")
        
        # 生成密钥
        key_gen_start = time.time()
        try:
            if key_type == 'weak_smooth':
                pub, priv, (p, q) = generate_weak_smooth_keys(bits, smoothness_bound)
            elif key_type == 'safe_prime':
                pub, priv, (p, q) = generate_safe_prime_keys(bits)
            else:
                raise ValueError(f"未知密钥类型: {key_type}")
        except Exception as ex:
            if verbose:
                print(f"    密钥生成失败: {ex}")
            continue
        
        key_gen_time = time.time() - key_gen_start
        (n, e), (_, d) = pub, priv
        
        if verbose:
            print(f"    密钥生成耗时: {key_gen_time:.3f} 秒")
            print(f"    n = {n}")
            print(f"    p 位数: {p.bit_length()}, q 位数: {q.bit_length()}")
            
            if key_type == 'weak_smooth':
                p_smooth = is_b_smooth(p - 1, smoothness_bound)
                q_smooth = is_b_smooth(q - 1, smoothness_bound)
                p_max_factor = get_largest_prime_factor(p - 1)
                q_max_factor = get_largest_prime_factor(q - 1)
                print(f"    p-1 是否 {smoothness_bound}-smooth: {p_smooth} (最大素因子: {p_max_factor})")
                print(f"    q-1 是否 {smoothness_bound}-smooth: {q_smooth} (最大素因子: {q_max_factor})")
            elif key_type == 'safe_prime':
                # safe_prime: p = 2q+1，所以 p-1 = 2q
                p_factor = (p - 1) // 2
                q_factor = (q - 1) // 2
                print(f"    p = 2*{p_factor} + 1 (safe prime)")
                print(f"    q = 2*{q_factor} + 1 (safe prime)")
        
        # 执行攻击
        attack_result = test_pollards_p_minus_1(n, p, q, B1, B2)
        
        trial_data = {
            'trial_num': trial_num + 1,
            'n': n,
            'p_true': p,
            'q_true': q,
            'key_gen_time': key_gen_time,
            **attack_result
        }
        
        results['trials'].append(trial_data)
        total_time += attack_result['time_seconds']
        
        if attack_result['success']:
            results['success_count'] += 1
            success_time += attack_result['time_seconds']
            if verbose:
                print(f"    攻击成功！耗时: {attack_result['time_seconds']:.3f} 秒")
        else:
            failed_time += attack_result['time_seconds']
            if verbose:
                print(f"    攻击失败。耗时: {attack_result['time_seconds']:.3f} 秒")
    
    # 计算统计数据
    if num_trials > 0:
        results['ASR'] = results['success_count'] / num_trials
        results['avg_time_all'] = total_time / num_trials
    
    if results['success_count'] > 0:
        results['avg_time_success'] = success_time / results['success_count']
    
    failed_count = num_trials - results['success_count']
    if failed_count > 0:
        results['avg_time_failed'] = failed_time / failed_count
    
    if verbose:
        print(f"\n{'='*70}")
        print(f"批量测试完成")
        print(f"{'='*70}")
        print(f"攻击成功率 (ASR): {results['ASR']*100:.1f}% ({results['success_count']}/{num_trials})")
        print(f"平均攻击时间: {results['avg_time_all']:.3f} 秒")
        if results['success_count'] > 0:
            print(f"成功案例平均时间: {results['avg_time_success']:.3f} 秒")
    
    return results

# ============ 主实验函数 ============

def run_experiment_2():
    """
    实验二：展示 safe_prime 对 Pollard's p-1 攻击的防御效果
    """
    print("\n" + "="*70)
    print("实验二：RSA 防御措施有效性测试")
    print("="*70)
    print("\n实验目标：展示 safe_prime 对 Pollard's p-1 的防御效果")
    print("\n对比：")
    print("  - weak_smooth: p-1 是 B-smooth（所有素因子 ≤ B），容易被攻破")
    print("  - safe_prime:  p = 2q+1（q 是大素数），p-1 = 2q 不是 B-smooth")
    print("\n" + "="*70)
    
    all_results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # ========== 场景 1: 攻击 weak_smooth (256位, B=1000) ==========
    print("\n\n【场景 1】攻击 weak_smooth (256位, B=1000)")
    print("="*70)
    print("说明：smoothness_bound=1000 表示 p-1 的所有素因子 ≤ 1000")
    result_weak_smooth_256_b1000 = run_experiment_batch(
        key_type='weak_smooth',
        bits=256,
        num_trials=10,
        smoothness_bound=1000,
        B1=10_000,
        B2=100_000
    )
    all_results.append(result_weak_smooth_256_b1000)
    
    # ========== 场景 2: 攻击 weak_smooth (256位, B=5000) ==========
    print("\n\n【场景 2】攻击 weak_smooth (256位, B=5000)")
    print("="*70)
    print("说明：smoothness_bound=5000，稍大一些，攻击难度增加")
    result_weak_smooth_256_b5000 = run_experiment_batch(
        key_type='weak_smooth',
        bits=256,
        num_trials=5,
        smoothness_bound=5000,
        B1=50_000,
        B2=500_000
    )
    all_results.append(result_weak_smooth_256_b5000)
    
    # ========== 场景 3: 攻击 safe_prime (256位) ==========
    if DEFENSE_AVAILABLE:
        print("\n\n【场景 3】攻击 safe_prime (256位) - 防御展示")
        print("="*70)
        print("说明：safe_prime 的 p = 2q+1，p-1 = 2q 包含大素因子 q，不是 B-smooth")
        result_safe_prime_256 = run_experiment_batch(
            key_type='safe_prime',
            bits=256,
            num_trials=5,
            B1=50_000,
            B2=500_000
        )
        all_results.append(result_safe_prime_256)
    else:
        print("\n警告：safe_prime 测试跳过（RSA_Defense 模块不可用）")
    
    # ========== 保存结果 ==========
    save_results(all_results, timestamp)
    
    # ========== 打印对比分析 ==========
    print_defense_comparison(all_results)
    
    return all_results

def save_results(results: List[Dict], timestamp: str):
    """保存实验结果到 JSON 文件"""
    import os
    
    os.makedirs('test_results', exist_ok=True)
    
    def convert_large_ints(obj):
        if isinstance(obj, dict):
            return {k: convert_large_ints(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_large_ints(item) for item in obj]
        elif isinstance(obj, int) and obj.bit_length() > 53:
            return str(obj)
        else:
            return obj
    
    results_serializable = convert_large_ints(results)
    
    output_file = f"test_results/experiment_2_defense_{timestamp}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results_serializable, f, indent=2, ensure_ascii=False)
    
    print(f"\n结果已保存到: {output_file}")

def print_defense_comparison(results: List[Dict]):
    """打印防御效果对比分析"""
    print("\n\n" + "="*70)
    print("实验二：防御效果对比分析")
    print("="*70)
    
    # 汇总表
    print("\n【攻击成功率 (ASR) 汇总】")
    print("-"*70)
    print(f"{'密钥类型':<20} {'位数':<8} {'ASR':<10} {'成功/总数':<12} {'平均时间(秒)'}")
    print("-"*70)
    
    for result in results:
        key_type = result['key_type']
        bits = result['bits']
        asr = result['ASR'] * 100
        success = f"{result['success_count']}/{result['num_trials']}"
        avg_time = result['avg_time_all']
        
        print(f"{key_type:<20} {bits:<8} {asr:>5.1f}% {' ':<4} {success:<12} {avg_time:>10.3f}")
    
    print("-"*70)
    
    # 详细对比
    print("\n【关键发现】")
    print("-"*70)
    
    weak_smooth_results = [r for r in results if r['key_type'] == 'weak_smooth']
    safe_prime_results = [r for r in results if r['key_type'] == 'safe_prime']
    
    if weak_smooth_results:
        print("\n弱密钥 (weak_smooth):")
        for r in weak_smooth_results:
            print(f"  - {r['bits']:3d} 位: ASR = {r['ASR']*100:5.1f}%")
    
    if safe_prime_results:
        print("\n防御密钥 (safe_prime):")
        for r in safe_prime_results:
            print(f"  - {r['bits']:3d} 位: ASR = {r['ASR']*100:5.1f}%")
        
        print("\n结论: safe_prime 有效防御 Pollard's p-1 攻击")
        print("   - weak_smooth 的 p-1 是 B-smooth，容易被攻破")
        print("   - safe_prime 的 p-1 = 2q（q 是大素数），不是 B-smooth")
    
    print("\n" + "="*70)

def quick_test():
    """快速测试"""
    print("\n快速测试模式 - 实验二")
    print("="*70)
    print("\n注意：使用更小的 smoothness_bound 以提高攻击成功率")
    print("   - smoothness_bound 越小，p-1 的素因子越小，越容易被攻破")
    print("   - 实际场景中，弱密钥可能使用 B=1000 左右\n")
    
    all_results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("\n1. weak_smooth (256位, B=1000):")
    result1 = run_experiment_batch(
        key_type='weak_smooth',
        bits=256,
        num_trials=5,
        smoothness_bound=1000,
        B1=10_000,
        B2=100_000
    )
    all_results.append(result1)
    
    if DEFENSE_AVAILABLE:
        print("\n2. safe_prime (256位):")
        result2 = run_experiment_batch(
            key_type='safe_prime',
            bits=256,
            num_trials=3,
            B1=10_000,
            B2=100_000
        )
        all_results.append(result2)
    
    save_results(all_results, timestamp)
    print_defense_comparison(all_results)

if __name__ == "__main__":
    import sys
    
    print("\n" + "="*70)
    print("RSA 攻击与防御实验系统 - 实验二")
    print("="*70)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--quick':
        quick_test()
    else:
        print("\n请选择运行模式:")
        print("  1. 完整实验（推荐）")
        print("  2. 快速测试（用于验证代码）")
        
        choice = input("\n请输入选项 (1 或 2): ").strip()
        
        if choice == '1':
            run_experiment_2()
        elif choice == '2':
            quick_test()
        else:
            print("无效选项，退出。")
