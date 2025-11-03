# -*- coding: utf-8 -*-
"""
RSA 防御与攻击演示：完整集成示例
展示如何联动 RSA_python.py、RSA_Defense.py 和 RSA_Attack.py
"""

from RSA_python import generate_keys, encrypt, decrypt
from RSA_Defense import (
    validate_user_primes, 
    secure_generate_keys,
    defensive_generate_keys,
    is_probable_prime
)
from RSA_Attack import attack_and_decrypt, pollards_rho

def demo_weak_parameters_blocked():
    """演示 1：弱参数被防御系统拒绝"""
    print("=" * 70)
    print("演示 1：弱参数被防御系统拒绝")
    print("=" * 70)
    
    # 使用 RSA_python.py 中的小素数（教学示例）
    p_weak = 61
    q_weak = 53
    e_weak = 17
    
    print(f"\n尝试使用弱参数：")
    print(f"  p = {p_weak}")
    print(f"  q = {q_weak}")
    print(f"  e = {e_weak}")
    print(f"  n = {p_weak * q_weak} (位数: {(p_weak * q_weak).bit_length()})")
    
    # 方法 1：直接使用 RSA_python.py（不安全，但可以工作）
    print("\n【方法 1】使用 RSA_python.py 直接生成（不安全）：")
    try:
        pub_weak, priv_weak = generate_keys(p_weak, q_weak, e_weak)
        print(f"✅ 生成成功（但不安全！）")
        print(f"  公钥: {pub_weak}")
        
        # 演示攻击的有效性
        n, e = pub_weak
        print(f"\n尝试使用 Pollard's rho 攻击分解 n...")
        attack_result = attack_and_decrypt(n, e)
        print(f"⚠️  攻击成功！恢复的参数：")
        print(f"  p = {attack_result['p']}")
        print(f"  q = {attack_result['q']}")
        print(f"  d = {attack_result['d']}")
        print(f"  攻击结论：弱参数极易被破解！")
        
    except Exception as e:
        print(f"❌ 失败：{e}")
    
    # 方法 2：使用 RSA_Defense.py 的验证（会被拒绝）
    print(f"\n【方法 2】使用 RSA_Defense.py 验证（推荐）：")
    try:
        validate_user_primes(p_weak, q_weak, e_weak)
        pub_safe, priv_safe = secure_generate_keys(p_weak, q_weak, e_weak)
        print(f"✅ 验证通过并生成密钥")
    except ValueError as e:
        print(f"❌ 验证失败（这是好事！）：{e}")
        print(f"  结论：防御系统成功阻止了弱参数的使用！")

def demo_strong_parameters_protected():
    """演示 2：强参数可以抵御攻击"""
    print("\n" + "=" * 70)
    print("演示 2：强参数可以抵御攻击（2048 位密钥）")
    print("=" * 70)
    
    print("\n正在生成 2048 位强化密钥对...")
    print("（这需要一些时间，请耐心等待...）")
    
    # 使用防御系统生成强密钥
    pub, priv, (p, q) = defensive_generate_keys(bits=2048)
    n, e = pub
    n2, d = priv
    
    print(f"\n✅ 生成成功！")
    print(f"  n 位数 = {n.bit_length()}")
    print(f"  p 位数 = {p.bit_length()}")
    print(f"  q 位数 = {q.bit_length()}")
    print(f"  e = {e}")
    
    # 测试加解密
    print(f"\n测试加解密功能：")
    m = 999888777666
    print(f"  原始明文 M = {m}")
    c = encrypt(m, pub)
    print(f"  加密后密文 C = {c}")
    m2 = decrypt(c, priv)
    print(f"  解密后明文 M' = {m2}")
    print(f"  验证：{'✅ 成功' if m == m2 else '❌ 失败'}")
    
    # 尝试攻击（会失败）
    print(f"\n尝试使用 Pollard's rho 攻击分解 n...")
    print(f"（对于 2048 位密钥，这在实际时间内不可行）")
    print(f"  n = {n}")
    print(f"  尝试分解...（限制步数以避免长时间等待）")
    
    # 限制攻击步数，因为2048位密钥无法在合理时间内破解
    factor = pollards_rho(n, max_steps=10000, max_tries=5)
    if factor is None or factor == 1 or factor == n:
        print(f"  ✅ 攻击失败（这是好事！）")
        print(f"  结论：2048 位强密钥可以有效抵御 Pollard's rho 攻击！")
    else:
        print(f"  ⚠️  意外：找到因子 {factor}")

def demo_user_input_validation():
    """演示 3：用户输入参数的验证流程"""
    print("\n" + "=" * 70)
    print("演示 3：用户输入参数的验证流程")
    print("=" * 70)
    
    # 测试不同的参数组合
    test_cases = [
        {
            "name": "相同的素数 (p == q)",
            "p": 1009,
            "q": 1009,
            "e": 65537,
            "should_pass": False
        },
        {
            "name": "e 与 (p-1) 不互质",
            "p": 103,  # p-1 = 102 = 2 * 3 * 17
            "q": 107,
            "e": 17,   # gcd(17, 102) = 17 != 1
            "should_pass": False
        },
        {
            "name": "模数位数太小",
            "p": 1009,
            "q": 1013,
            "e": 65537,
            "should_pass": False
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n【测试案例 {i}】{test['name']}")
        print(f"  参数：p={test['p']}, q={test['q']}, e={test['e']}")
        print(f"  n = {test['p'] * test['q']} (位数: {(test['p'] * test['q']).bit_length()})")
        
        try:
            validate_user_primes(test['p'], test['q'], test['e'])
            result = "✅ 通过"
        except ValueError as ex:
            result = f"❌ 拒绝 - {ex}"
        
        print(f"  验证结果：{result}")
        expected = "应该通过" if test['should_pass'] else "应该拒绝"
        print(f"  预期结果：{expected}")

def demo_comparison():
    """演示 4：RSA_python.py vs RSA_Defense.py 对比"""
    print("\n" + "=" * 70)
    print("演示 4：RSA_python.py vs RSA_Defense.py 功能对比")
    print("=" * 70)
    
    print("""
┌─────────────────────────┬──────────────────┬─────────────────────┐
│ 功能                    │ RSA_python.py    │ RSA_Defense.py      │
├─────────────────────────┼──────────────────┼─────────────────────┤
│ 基础 RSA 实现           │ ✅ 支持          │ ✅ 支持             │
│ 用户自定义 p, q, e     │ ✅ 支持          │ ✅ 支持 (带验证)    │
│ 参数安全性验证          │ ❌ 不验证        │ ✅ 严格验证         │
│ 最小密钥位数要求        │ ❌ 无限制        │ ✅ 2048 位最低      │
│ 强素数生成              │ ❌ 不支持        │ ✅ Gordon 算法      │
│ 素性测试                │ ❌ 无            │ ✅ Miller-Rabin     │
│ 防止 p == q             │ ✅ 检查          │ ✅ 检查             │
│ 防止 p, q 过近          │ ❌ 不检查        │ ✅ 检查             │
│ 检查 e 与 φ(n) 互质     │ ✅ 检查          │ ✅ 增强检查         │
│ 抵御 Pollard's rho      │ ❌ 弱            │ ✅ 强 (大密钥)      │
│ 抵御 Pollard's p-1      │ ❌ 不防御        │ ✅ 强素数防御       │
│ 抵御 Williams' p+1      │ ❌ 不防御        │ ✅ 强素数防御       │
│ 抵御费马分解            │ ❌ 弱            │ ✅ 检查 p, q 距离   │
│ 侧信道攻击防护          │ ❌ 无            │ ✅ 可选盲化解密     │
│ CSPRNG 随机数生成       │ ❌ 无            │ ✅ secrets 模块     │
│ 适用场景                │ 教学/演示        │ 实际安全应用        │
└─────────────────────────┴──────────────────┴─────────────────────┘

【使用建议】
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. 学习 RSA 原理 → 使用 RSA_python.py
   - 简单直观，便于理解基本流程
   - 可以用小素数快速测试

2. 实际安全应用 → 使用 RSA_Defense.py
   - 强制安全参数要求
   - 自动生成强素数
   - 全面的参数验证

3. 集成现有代码 → 联动使用
   - 从 RSA_python.py 导入基础函数
   - 从 RSA_Defense.py 导入验证和强化功能
   - 享受两者优势
    """)

def main():
    """主演示程序"""
    print("\n" + "=" * 70)
    print("RSA 防御系统集成演示")
    print("展示 RSA_python.py、RSA_Defense.py 和 RSA_Attack.py 的联动")
    print("=" * 70)
    
    demos = [
        ("演示 1：弱参数被防御系统拒绝", demo_weak_parameters_blocked),
        ("演示 2：强参数可以抵御攻击", demo_strong_parameters_protected),
        ("演示 3：用户输入参数的验证流程", demo_user_input_validation),
        ("演示 4：功能对比总结", demo_comparison),
    ]
    
    while True:
        print("\n请选择要运行的演示：")
        for i, (name, _) in enumerate(demos, 1):
            print(f"  {i}. {name}")
        print(f"  {len(demos) + 1}. 运行所有演示")
        print(f"  {len(demos) + 2}. 退出")
        
        choice = input("\n请输入选项: ").strip()
        
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(demos):
                demos[choice_num - 1][1]()
                input("\n按 Enter 继续...")
            elif choice_num == len(demos) + 1:
                for name, func in demos:
                    func()
                    print("\n" + "-" * 70)
                input("\n所有演示完成！按 Enter 继续...")
            elif choice_num == len(demos) + 2:
                print("\n感谢使用！再见。")
                break
            else:
                print("❌ 无效选项，请重新选择。")
        except ValueError:
            print("❌ 请输入有效的数字。")
        except KeyboardInterrupt:
            print("\n\n操作已取消。")
            break

if __name__ == "__main__":
    main()

