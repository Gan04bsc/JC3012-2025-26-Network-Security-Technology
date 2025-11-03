# RSA 防御系统使用说明

## 📚 文件说明

本目录包含完整的 RSA 加密系统，包括基础实现、攻击演示和防御措施：

| 文件 | 说明 | 用途 |
|------|------|------|
| `RSA_python.py` | RSA 基础实现 | 教学演示，理解 RSA 基本原理 |
| `RSA_Attack.py` | Pollard's rho 攻击 | 演示针对弱密钥的攻击方法 |
| `RSA_Defense.py` | 安全防御系统 | 生产环境使用，包含完整防御措施 |
| `demo_integration.py` | 集成演示 | 展示三个模块的联动使用 |

---

## 🛡️ 防御措施总览

`RSA_Defense.py` 实现了以下针对 RSA 攻击的防御措施：

### 1. 使用足够大的模数（n）

- **强制要求**：密钥位数 ≥ 2048 位
- **原理**：Pollard's rho 算法复杂度为 O(√p)，密钥长度加倍时攻击难度呈指数级上升
- **实践标准**：
  - 一般系统：2048 位（最低安全标准，TLS/SSL 标准）
  - 高安全系统：3072 位或 4096 位
  - 本代码默认：2048 位

### 2. 生成强素数（Strong Primes）

**强素数条件**：
- ✅ p 是大素数
- ✅ p-1 含有大素因子 r（抵抗 Pollard's p-1 攻击）
- ✅ p+1 含有大素因子 s（抵抗 Williams' p+1 攻击）
- ✅ r-1 也含有大素因子（增强安全层次）

**生成方法**：
- 使用 CSPRNG（密码学安全伪随机数生成器）
- Miller-Rabin 概率素性测试（64 轮）
- Gordon 算法风格的强素数构造
- 确保 gcd(e, p-1) = gcd(e, q-1) = 1

### 3. 参数安全验证

`validate_user_primes(p, q, e)` 函数检查：
- ✅ p, q 必须为不同的素数
- ✅ 模数 n 位数必须 ≥ 2048 位
- ✅ p 与 q 不能过于接近（防止费马分解）
- ✅ e 必须与 (p-1) 和 (q-1) 互质
- ✅ e 必须为奇数且 ≥ 3（推荐 65537）

### 4. 可选的侧信道防护

- `rsa_blinded_decrypt()`: 使用随机数 r 对解密过程进行盲化，防止基于时间的侧信道攻击

---

## 🚀 使用方法

### 方法 1：自动生成强化密钥对（推荐）

```python
from RSA_Defense import defensive_generate_keys, encrypt, decrypt

# 生成 2048 位强化密钥对
pub, priv, (p, q) = defensive_generate_keys(bits=2048)
(n, e), (n2, d) = pub, priv

# 加密
message = 123456789
ciphertext = encrypt(message, pub)

# 解密
plaintext = decrypt(ciphertext, priv)
```

### 方法 2：验证用户输入的参数

```python
from RSA_Defense import validate_user_primes, secure_generate_keys, encrypt, decrypt

# 用户提供的参数
p = ...  # 大素数
q = ...  # 大素数
e = 65537

# 验证参数（如果不安全会抛出 ValueError）
validate_user_primes(p, q, e)

# 验证通过后生成密钥
pub, priv = secure_generate_keys(p, q, e)

# 正常使用
ciphertext = encrypt(message, pub)
plaintext = decrypt(ciphertext, priv)
```

### 方法 3：联动 RSA_python.py（教学场景）

```python
from RSA_python import encrypt, decrypt
from RSA_Defense import validate_user_primes

# 用户输入参数
p = int(input("请输入素数 p: "))
q = int(input("请输入素数 q: "))
e = int(input("请输入 e: "))

try:
    # 先验证参数安全性
    validate_user_primes(p, q, e)
    
    # 验证通过后使用 RSA_python 的函数
    from RSA_python import generate_keys
    pub, priv = generate_keys(p, q, e)
    
    print("✅ 参数安全，密钥生成成功！")
    
except ValueError as e:
    print(f"❌ 参数不安全: {e}")
    print("建议使用 defensive_generate_keys() 自动生成安全密钥")
```

---

## 💻 交互式使用

### 运行防御系统主程序

```bash
python RSA_Defense.py
```

提供以下功能：
1. 自动生成强化密钥对（推荐）
2. 验证用户输入的参数
3. 安全对比演示（弱参数 vs 强参数）
4. 查看防御措施说明
5. 退出

### 运行集成演示程序

```bash
python demo_integration.py
```

提供以下演示：
1. 演示弱参数被防御系统拒绝
2. 演示强参数可以抵御攻击
3. 用户输入参数的验证流程
4. 功能对比总结

---

## 🔬 技术细节

### Miller-Rabin 素性测试

使用 64 轮 Miller-Rabin 测试，错误率低于 2^(-128)，确保生成的素数几乎确定为真素数。

```python
from RSA_Defense import is_probable_prime

p = 2**1024 + 643  # 某个候选数
if is_probable_prime(p, rounds=64):
    print("p 是素数（概率极高）")
```

### Gordon 风格强素数生成

实现步骤：
1. 生成大素数 r（safe prime）
2. 生成大素数 s（safe prime）
3. 构造 p₀ = 2rs + 1 为素数，使 r | (p₀-1)
4. 调整 p = p₀ + k·(2rs)，使 s | (p+1)
5. 测试 p 的素性，不是素数则继续调整

```python
from RSA_Defense import generate_strong_prime

# 生成 2048 位强素数（需要一些时间）
p = generate_strong_prime(2048)
```

### 参数验证详解

```python
def validate_user_primes(p, q, e, min_bits=2048):
    # 1. 基本检查
    assert p != q and p > 1 and q > 1
    
    # 2. 素性测试
    assert is_probable_prime(p) and is_probable_prime(q)
    
    # 3. 模数位数检查
    n = p * q
    assert n.bit_length() >= min_bits
    
    # 4. p, q 距离检查（防止费马分解）
    assert abs(p - q).bit_length() >= min_bits // 2 - 24
    
    # 5. e 的有效性
    assert e >= 3 and e % 2 == 1
    assert gcd(e, p-1) == 1 and gcd(e, q-1) == 1
```

---

## ⚔️ 对抗的攻击方法

本防御系统可以有效抵御以下攻击：

| 攻击方法 | 攻击原理 | 防御措施 |
|---------|---------|---------|
| Pollard's rho | 因式分解 n | 使用 2048+ 位密钥，复杂度过高 |
| Pollard's p-1 | 利用 p-1 的小因子 | 强素数确保 p-1 含大素因子 |
| Williams' p+1 | 利用 p+1 的小因子 | 强素数确保 p+1 含大素因子 |
| 费马分解 | 利用 p, q 接近 | 验证 \|p-q\| 足够大 |
| 小素数攻击 | 直接试除小素数 | 强制最小密钥位数 |
| 弱 e 攻击 | e 与 φ(n) 不互质 | 验证 gcd(e, p-1) = gcd(e, q-1) = 1 |
| 侧信道攻击 | 时间分析 | 可选盲化解密 |

---

## 📊 性能与时间

生成强素数需要较长时间，以下是参考值（实际时间依硬件而定）：

| 密钥位数 | p, q 位数 | 生成时间（估计） |
|---------|-----------|-----------------|
| 2048 位 | 1024 位   | 5-30 秒 |
| 3072 位 | 1536 位   | 30-120 秒 |
| 4096 位 | 2048 位   | 2-10 分钟 |

**建议**：
- 开发测试：使用 2048 位
- 生产环境：预先生成密钥对并存储
- 高安全需求：使用 3072 或 4096 位，但接受较长生成时间

---

## ⚠️ 注意事项

1. **密钥存储**：生成的密钥对应妥善保管，私钥 d 绝不能泄露
2. **随机数质量**：使用 `secrets` 模块（CSPRNG）保证随机数的密码学安全性
3. **量子计算威胁**：RSA 在量子计算机面前不安全，未来需考虑后量子密码学
4. **填充方案**：本实现未包含填充（如 OAEP），实际应用应添加
5. **整数消息限制**：消息必须满足 0 ≤ M < n

---

## 🔗 相关资源

- [RSA 加密算法 - Wikipedia](https://zh.wikipedia.org/wiki/RSA加密演算法)
- [Pollard's rho 算法](https://zh.wikipedia.org/wiki/Pollard_ρ因数分解算法)
- [Strong Prime - Wikipedia](https://en.wikipedia.org/wiki/Strong_prime)
- [Miller-Rabin 素性测试](https://zh.wikipedia.org/wiki/米勒-拉宾素性测试)
- NIST 密钥管理建议：[Special Publication 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## 📝 示例输出

### 自动生成强化密钥对

```
============================================================
方案 A：自动生成强化密钥对
============================================================
参数：密钥位数 = 2048，e = 65537
正在生成强素数 p, q...
（这可能需要几秒钟到几十秒，请耐心等待）

✅ 生成成功！

密钥参数：
  n 位数 = 2048 位
  p 位数 = 1024 位
  q 位数 = 1024 位
  e = 65537
  d 位数 = 2047 位

============================================================
加解密测试
============================================================
原始明文 M = 123456789
加密后密文 C = 123...
解密后明文 M' = 123456789
验证结果：OK ✅
```

### 弱参数被拒绝

```
请输入素数 p: 61
请输入素数 q: 53
请输入公钥指数 e: 17

正在验证参数安全性...
  - 检查 p, q 是否为素数...
  - 检查密钥位数是否满足最低要求 (2048 位)...
  
❌ 参数验证失败：模数位数过小（12 位），请至少使用 2048 位。

说明：
  您输入的参数不满足安全要求。
  建议使用方案 A 自动生成强化密钥对，或重新输入符合要求的参数。
```

---

## 👨‍💻 作者与许可

本代码用于教学和研究目的，展示 RSA 加密的防御措施。

**免责声明**：本代码仅用于教育目的，不应直接用于生产环境。实际应用应使用经过充分测试的密码学库（如 cryptography、PyCryptodome 等）。

