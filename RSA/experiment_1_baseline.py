# -*- coding: utf-8 -*-
"""
experiment_1_baseline.py
实验一：在不执行防御代码的情况下，测评攻击代码对初始RSA的攻击效果

实验设计：
1. 小模数 baseline（64/80/96/112/128 位）- 展示 rho 在小模数上的成功率从高到低
2. 大模数 baseline（256/512/1024 位）- 展示大模数防御效果（ASR≈0）
3. 256 位 weak_imbalanced - 展示失衡模数的脆弱性

关键指标：
- ASR (Attack Success Rate): 攻击成功率
- 平均攻击时间
- 成功案例的详细信息
"""

import time
import json
import secrets
from typing import Tuple, Optional, Dict, List
from datetime import datetime
from RSA_python import generate_keys, encrypt, modexp, modinv, gcd
from RSA_Attack import pollards_rho, attack_and_decrypt

# ============ 简单素数生成（不使用强素数防御） ============

def _trial_division_simple(n: int) -> bool:
    """简单的试除法素性测试"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    # 测试小素数
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
    
    # 将 n-1 写成 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # 进行 rounds 轮测试
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

def is_probable_prime_simple(n: int) -> bool:
    """组合素性测试"""
    if not _trial_division_simple(n):
        return False
    return _miller_rabin_simple(n)

def generate_prime_simple(bits: int) -> int:
    """生成指定位数的素数（baseline，不使用强素数）"""
    while True:
        # 生成随机奇数
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # 确保最高位为 1
        candidate |= 1  # 确保是奇数
        
        if is_probable_prime_simple(candidate):
            return candidate

# ============ 密钥生成函数 ============

def generate_baseline_keys(bits: int, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    生成基线（均衡）密钥对：p 和 q 位数相近
    返回：((n, e), (n, d), (p, q))
    """
    half = bits // 2
    
    # 生成两个均衡的素数
    p = generate_prime_simple(half)
    q = generate_prime_simple(half)
    
    # 确保 p != q
    while p == q:
        q = generate_prime_simple(half)
    
    # 确保与 e 互质
    while gcd(e, (p - 1)) != 1:
        p = generate_prime_simple(half)
    while gcd(e, (q - 1)) != 1:
        q = generate_prime_simple(half)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    
    return (n, e), (n, d), (p, q)

def generate_weak_imbalanced_keys(total_bits: int, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    生成失衡的弱密钥对：p 很小（40 位），q 很大
    这样的密钥容易被 Pollard's rho 攻击
    返回：((n, e), (n, d), (p, q))
    """
    p_bits = 40  # p 固定为 40 位（很小，容易被分解）
    q_bits = total_bits - p_bits
    
    # 生成小的 p
    p = generate_prime_simple(p_bits)
    while gcd(e, (p - 1)) != 1:
        p = generate_prime_simple(p_bits)
    
    # 生成大的 q
    q = generate_prime_simple(q_bits)
    while gcd(e, (q - 1)) != 1 or p == q:
        q = generate_prime_simple(q_bits)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    
    return (n, e), (n, d), (p, q)

# ============ 攻击测试函数 ============

def test_single_attack(n: int, e: int, p_true: int, q_true: int, 
                      max_steps: int, max_tries: int, 
                      test_decrypt: bool = False) -> Dict:
    """
    对单个密钥进行攻击测试
    
    返回：
    {
        'success': bool,
        'time_seconds': float,
        'p_found': int or None,
        'q_found': int or None,
        'steps_used': int or None,
        'decryption_correct': bool or None  # 如果测试解密
    }
    """
    result = {
        'success': False,
        'time_seconds': 0.0,
        'p_found': None,
        'q_found': None,
        'decryption_correct': None
    }
    
    start_time = time.time()
    
    try:
        # 使用 Pollard's rho 攻击
        factor = pollards_rho(n, max_steps=max_steps, max_tries=max_tries)
        
        if factor is not None and 1 < factor < n:
            p_found = factor
            q_found = n // factor
            
            # 确保 p_found < q_found
            if p_found > q_found:
                p_found, q_found = q_found, p_found
            
            # 验证分解是否正确
            if p_found * q_found == n:
                result['success'] = True
                result['p_found'] = p_found
                result['q_found'] = q_found
                
                # 如果需要，测试解密
                if test_decrypt:
                    phi = (p_found - 1) * (q_found - 1)
                    d_recovered = modinv(e, phi)
                    
                    # 生成随机明文测试
                    m_test = secrets.randbelow(n - 1) + 1
                    c_test = modexp(m_test, e, n)
                    m_decrypted = modexp(c_test, d_recovered, n)
                    
                    result['decryption_correct'] = (m_test == m_decrypted)
    
    except Exception as ex:
        result['error'] = str(ex)
    
    result['time_seconds'] = time.time() - start_time
    
    return result

def run_experiment_batch(bits: int, mode: str, num_trials: int = 10, 
                        max_steps: int = None, max_tries: int = 20) -> Dict:
    """
    对指定配置进行批量测试
    
    参数：
    - bits: 模数位数
    - mode: 'baseline' 或 'weak_imbalanced'
    - num_trials: 测试次数
    - max_steps: Pollard's rho 最大步数（None 则自动设置）
    - max_tries: Pollard's rho 最大重启次数
    
    返回：统计结果
    """
    print(f"\n{'='*70}")
    print(f"测试配置: {bits} 位, 模式={mode}")
    print(f"{'='*70}")
    
    # 根据位数自动设置 max_steps
    if max_steps is None:
        if bits <= 64:
            max_steps = 2_000_000
        elif bits <= 80:
            max_steps = 10_000_000
        elif bits <= 96:
            max_steps = 50_000_000
        else:
            max_steps = 50_000_000  # 更大的位数基本不可能成功，但保持一致
    
    results = {
        'bits': bits,
        'mode': mode,
        'num_trials': num_trials,
        'max_steps': max_steps,
        'max_tries': max_tries,
        'trials': [],
        'success_count': 0,
        'avg_time_all': 0.0,
        'avg_time_success': 0.0,
        'avg_time_failed': 0.0,
        'ASR': 0.0  # Attack Success Rate
    }
    
    total_time = 0.0
    success_time = 0.0
    failed_time = 0.0
    
    for trial_num in range(num_trials):
        print(f"\n  试验 {trial_num + 1}/{num_trials}...")
        
        # 生成密钥
        key_gen_start = time.time()
        if mode == 'baseline':
            pub, priv, (p, q) = generate_baseline_keys(bits)
        elif mode == 'weak_imbalanced':
            pub, priv, (p, q) = generate_weak_imbalanced_keys(bits)
        else:
            raise ValueError(f"未知模式: {mode}")
        
        key_gen_time = time.time() - key_gen_start
        (n, e), (_, d) = pub, priv
        
        print(f"    密钥生成耗时: {key_gen_time:.3f} 秒")
        print(f"    n = {n}")
        print(f"    p 位数: {p.bit_length()}, q 位数: {q.bit_length()}")
        
        # 执行攻击
        attack_result = test_single_attack(
            n, e, p, q, 
            max_steps=max_steps, 
            max_tries=max_tries,
            test_decrypt=True
        )
        
        trial_data = {
            'trial_num': trial_num + 1,
            'n': n,
            'e': e,
            'p_true': p,
            'q_true': q,
            'n_bits': n.bit_length(),
            'p_bits': p.bit_length(),
            'q_bits': q.bit_length(),
            'key_gen_time': key_gen_time,
            **attack_result
        }
        
        results['trials'].append(trial_data)
        total_time += attack_result['time_seconds']
        
        if attack_result['success']:
            results['success_count'] += 1
            success_time += attack_result['time_seconds']
            print(f"    ✅ 攻击成功！耗时: {attack_result['time_seconds']:.3f} 秒")
            print(f"    分解结果: p={attack_result['p_found']}, q={attack_result['q_found']}")
        else:
            failed_time += attack_result['time_seconds']
            print(f"    ❌ 攻击失败。耗时: {attack_result['time_seconds']:.3f} 秒")
    
    # 计算统计数据
    results['ASR'] = results['success_count'] / num_trials
    results['avg_time_all'] = total_time / num_trials
    
    if results['success_count'] > 0:
        results['avg_time_success'] = success_time / results['success_count']
    
    failed_count = num_trials - results['success_count']
    if failed_count > 0:
        results['avg_time_failed'] = failed_time / failed_count
    
    print(f"\n{'='*70}")
    print(f"批量测试完成")
    print(f"{'='*70}")
    print(f"攻击成功率 (ASR): {results['ASR']*100:.1f}% ({results['success_count']}/{num_trials})")
    print(f"平均攻击时间: {results['avg_time_all']:.3f} 秒")
    if results['success_count'] > 0:
        print(f"成功案例平均时间: {results['avg_time_success']:.3f} 秒")
    if failed_count > 0:
        print(f"失败案例平均时间: {results['avg_time_failed']:.3f} 秒")
    
    return results

# ============ 主实验函数 ============

def run_experiment_1():
    """
    实验一主函数：测试不同配置下 Pollard's rho 的攻击效果
    """
    print("\n" + "="*70)
    print("实验一：RSA 基线攻击效果测试")
    print("="*70)
    print("\n实验目标：")
    print("1. 展示 Pollard's rho 在小模数上的攻击效果（64-128 位）")
    print("2. 展示大模数防御效果（256-1024 位）")
    print("3. 展示失衡模数的脆弱性（256 位 weak_imbalanced）")
    print("\n" + "="*70)
    
    all_results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # ========== 场景 1: 小模数 baseline ==========
    print("\n\n【场景 1】小模数 baseline - 展示 ASR 从高到低的趋势")
    print("="*70)
    
    small_bits_configs = [
        (64, 10, 2_000_000),      # 64 位，10 次试验
        (80, 10, 10_000_000),     # 80 位，10 次试验
        (96, 8, 50_000_000),      # 96 位，8 次试验（更费时）
        (112, 5, 50_000_000),     # 112 位，5 次试验（费时）
        (128, 3, 50_000_000),     # 128 位，3 次试验（很费时）
    ]
    
    for bits, trials, steps in small_bits_configs:
        result = run_experiment_batch(
            bits=bits,
            mode='baseline',
            num_trials=trials,
            max_steps=steps,
            max_tries=20
        )
        all_results.append(result)
    
    # ========== 场景 2: 大模数 baseline ==========
    print("\n\n【场景 2】大模数 baseline - 展示大模数防御效果")
    print("="*70)
    
    large_bits_configs = [
        (256, 5, 50_000_000),     # 256 位，5 次试验
        (512, 3, 50_000_000),     # 512 位，3 次试验
        # 1024 位通常不会成功，可以少测几次
        # (1024, 2, 50_000_000),  # 可选：1024 位
    ]
    
    for bits, trials, steps in large_bits_configs:
        result = run_experiment_batch(
            bits=bits,
            mode='baseline',
            num_trials=trials,
            max_steps=steps,
            max_tries=20
        )
        all_results.append(result)
    
    # ========== 场景 3: 256 位失衡模数 ==========
    print("\n\n【场景 3】256 位 weak_imbalanced - 展示失衡模数的脆弱性")
    print("="*70)
    
    result = run_experiment_batch(
        bits=256,
        mode='weak_imbalanced',
        num_trials=10,
        max_steps=50_000_000,
        max_tries=20
    )
    all_results.append(result)
    
    # ========== 保存结果 ==========
    output_file = f"test_results/experiment_1_baseline_{timestamp}.json"
    save_results(all_results, output_file)
    
    # ========== 打印总结 ==========
    print_experiment_summary(all_results, timestamp)
    
    return all_results

# ============ 结果保存和展示 ============

def save_results(results: List[Dict], filename: str):
    """保存实验结果到 JSON 文件"""
    import os
    
    # 确保目录存在
    os.makedirs('test_results', exist_ok=True)
    
    # 转换大整数为字符串（JSON 不支持任意大整数）
    def convert_large_ints(obj):
        if isinstance(obj, dict):
            return {k: convert_large_ints(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_large_ints(item) for item in obj]
        elif isinstance(obj, int) and obj.bit_length() > 53:  # JavaScript 安全整数范围
            return str(obj)
        else:
            return obj
    
    results_serializable = convert_large_ints(results)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results_serializable, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 结果已保存到: {filename}")

def print_experiment_summary(results: List[Dict], timestamp: str):
    """打印实验总结"""
    print("\n\n" + "="*70)
    print("实验一总结报告")
    print("="*70)
    print(f"实验时间: {timestamp}")
    print(f"总配置数: {len(results)}\n")
    
    # 按场景分组
    print("【攻击成功率 (ASR) 汇总】")
    print("-"*70)
    print(f"{'位数':<10} {'模式':<20} {'ASR':<15} {'成功/总数':<15} {'平均时间(秒)':<15}")
    print("-"*70)
    
    for result in results:
        bits = result['bits']
        mode = result['mode']
        asr = result['ASR'] * 100
        success = f"{result['success_count']}/{result['num_trials']}"
        avg_time = result['avg_time_all']
        
        print(f"{bits:<10} {mode:<20} {asr:>6.1f}%{' ':<8} {success:<15} {avg_time:>10.3f}")
    
    print("-"*70)
    
    # 关键发现
    print("\n【关键发现】")
    print("-"*70)
    
    # 小模数趋势
    small_results = [r for r in results if r['mode'] == 'baseline' and r['bits'] <= 128]
    if small_results:
        print("\n1. 小模数 baseline（64-128 位）:")
        for r in sorted(small_results, key=lambda x: x['bits']):
            print(f"   - {r['bits']:3d} 位: ASR = {r['ASR']*100:5.1f}%")
        print("   结论: ASR 随位数增加而显著下降，展示了模数大小对安全性的影响")
    
    # 大模数效果
    large_results = [r for r in results if r['mode'] == 'baseline' and r['bits'] >= 256]
    if large_results:
        print("\n2. 大模数 baseline（≥256 位）:")
        for r in sorted(large_results, key=lambda x: x['bits']):
            print(f"   - {r['bits']:3d} 位: ASR = {r['ASR']*100:5.1f}%")
        if all(r['ASR'] == 0 for r in large_results):
            print("   结论: ✅ 大模数有效防御 Pollard's rho 攻击（ASR ≈ 0）")
        else:
            print("   结论: 大模数显著降低攻击成功率")
    
    # 失衡模数脆弱性
    weak_results = [r for r in results if r['mode'] == 'weak_imbalanced']
    if weak_results:
        print("\n3. 256 位 weak_imbalanced:")
        for r in weak_results:
            print(f"   - ASR = {r['ASR']*100:5.1f}%")
            if r['ASR'] > 0:
                print(f"   - 成功案例平均时间: {r['avg_time_success']:.3f} 秒")
        
        # 对比同位数的 baseline
        baseline_256 = next((r for r in results if r['mode'] == 'baseline' and r['bits'] == 256), None)
        if baseline_256:
            print(f"\n   对比 256 位 baseline: ASR = {baseline_256['ASR']*100:5.1f}%")
            print("   结论: ⚠️  失衡模数极其脆弱，即使位数足够大")
    
    print("\n" + "="*70)
    print("实验一完成！")
    print("="*70)
    
    # 生成文本报告
    report_file = f"test_results/experiment_1_summary_{timestamp}.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("实验一：RSA 基线攻击效果测试 - 总结报告\n")
        f.write("="*70 + "\n")
        f.write(f"实验时间: {timestamp}\n\n")
        
        f.write("【实验配置】\n")
        for i, result in enumerate(results, 1):
            f.write(f"\n配置 {i}:\n")
            f.write(f"  位数: {result['bits']}\n")
            f.write(f"  模式: {result['mode']}\n")
            f.write(f"  试验次数: {result['num_trials']}\n")
            f.write(f"  Max steps: {result['max_steps']}\n")
            f.write(f"  Max tries: {result['max_tries']}\n")
            f.write(f"  ASR: {result['ASR']*100:.1f}%\n")
            f.write(f"  成功次数: {result['success_count']}/{result['num_trials']}\n")
            f.write(f"  平均攻击时间: {result['avg_time_all']:.3f} 秒\n")
    
    print(f"✅ 文本报告已保存到: {report_file}")

# ============ 快速测试函数（用于调试） ============

def quick_test():
    """快速测试（用于调试）"""
    print("\n快速测试模式")
    print("="*70)
    
    # 只测试几个代表性配置
    configs = [
        (64, 'baseline', 3),
        (128, 'baseline', 2),
        (256, 'weak_imbalanced', 3),
    ]
    
    all_results = []
    for bits, mode, trials in configs:
        result = run_experiment_batch(
            bits=bits,
            mode=mode,
            num_trials=trials,
            max_steps=10_000_000,
            max_tries=10
        )
        all_results.append(result)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_results(all_results, f"test_results/experiment_1_quick_{timestamp}.json")
    print_experiment_summary(all_results, timestamp)

# ============ 主程序入口 ============

if __name__ == "__main__":
    import sys
    
    print("\n" + "="*70)
    print("RSA 攻击与防御实验系统 - 实验一")
    print("="*70)
    
    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == '--quick':
        quick_test()
    else:
        print("\n请选择运行模式:")
        print("  1. 完整实验（推荐，但耗时较长）")
        print("  2. 快速测试（用于验证代码，快速得到结果）")
        
        choice = input("\n请输入选项 (1 或 2): ").strip()
        
        if choice == '1':
            run_experiment_1()
        elif choice == '2':
            quick_test()
        else:
            print("无效选项，退出。")

