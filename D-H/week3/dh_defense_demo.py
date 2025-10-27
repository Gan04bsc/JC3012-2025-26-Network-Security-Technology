import random
import hmac
import hashlib
import json
from datetime import datetime

# --- 你的 Week 1 D-H 基础代码 (保持不变) ---

def is_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin素数检测算法"""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    if n in small_primes: return True
    for prime in small_primes:
        if n % prime == 0: return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def generate_dh_parameters() -> tuple[int, int]:
    """使用标准测试参数"""
    p = 23  # 标准测试素数
    g = 5   # 标准测试本原根
    return p, g

def generate_key_pair(p: int, g: int) -> tuple[int, int]:
    """生成DH密钥对 (私钥, 公钥)"""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(other_public_key: int, private_key: int, p: int) -> int:
    """计算共享密钥"""
    return pow(other_public_key, private_key, p)

# --- Week 3 新增：HMAC 防御实现 (根据 wk2.docx) ---

def int_to_bytes(x: int) -> bytes:
    """将整数转换为bytes，用于HMAC计算"""
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def generate_mac(key: bytes, message_int: int) -> bytes:
    """
    使用PSK计算公钥的HMAC
    
    """
    message_bytes = int_to_bytes(message_int)
    return hmac.new(key, message_bytes, hashlib.sha256).digest()

def verify_mac(key: bytes, message_int: int, received_mac: bytes) -> bool:
    """
    验证接收到的HMAC是否正确
    [cite: 181, 182]
    """
    computed_mac = generate_mac(key, message_int)
    # 使用 hmac.compare_digest 来防止时序攻击
    return hmac.compare_digest(computed_mac, received_mac)

# --- 你的 Week 2 攻击者代码 (保持不变) ---

class MITMAttacker:
    """中间人攻击者"""
    
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        # 攻击者生成自己的密钥对
        self.attacker_private, self.attacker_public = generate_key_pair(p, g)
        self.shared_with_client = None
        self.shared_with_server = None
        self.intercepted_messages = []

    def intercept_and_forge(self, original_public_key: int, original_mac: bytes, target: str) -> tuple[int, bytes]:
        """
        拦截消息并尝试伪造。
        攻击者没有PSK，所以它无法生成有效的MAC。
        它只能：
        1. 转发原始MAC (验证会失败，因为公钥变了)
        2. 随便伪造一个MAC (验证会失败)
        """
        print(f"  [Attacker] 拦截到来自 {target} 的公钥: {original_public_key}")
        print(f"  [Attacker] 拦截到来自 {target} 的MAC: {original_mac.hex()[:10]}...")
        
        # 攻击者用自己的公钥替换
        forged_public_key = self.attacker_public
        
        # 攻击者没有PSK，无法计算正确的MAC [cite: 193]
        # 只能伪造一个无效的MAC (例如，用原始MAC)
        forged_mac = original_mac 
        
        print(f"  [Attacker] 替换为自己的公钥: {forged_public_key}")
        print(f"  [Attacker] 转发一个无效的MAC: {forged_mac.hex()[:10]}...")
        
        # 记录用于后续计算密钥
        if target == 'Client':
            self.shared_with_client = compute_shared_secret(original_public_key, self.attacker_private, self.p)
        elif target == 'Server':
            self.shared_with_server = compute_shared_secret(original_public_key, self.attacker_private, self.p)
            
        return forged_public_key, forged_mac

# --- Week 3 核心任务：记录攻击防御结果 ---

def run_attack_on_defended_dh():
    """
    演示MITM攻击 *对抗* 启用了HMAC-PSK防御的D-H
    这是你需要为Week 3任务记录的结果。
    """
    print("="*60)
    print("开始演示：对 D-H (PSK+HMAC 防御) 的 MITM 攻击")
    print("="*60)

    # 1. 初始化阶段：Alice和Bob拥有一个预共享密钥(PSK)
    # [cite: 178]
    # 攻击者 *不知道* 这个密钥。
    PSK_ALICE_BOB = b"secure_pre_shared_key_for_auth_123!"

    p, g = generate_dh_parameters()
    attacker = MITMAttacker(p, g)

    print(f"公开参数: p={p}, g={g}")
    print(f"Alice和Bob的PSK: {PSK_ALICE_BOB.decode()}")
    print(f"攻击者公钥: {attacker.attacker_public}\n")

    attack_log = {
        'timestamp': datetime.now().isoformat(),
        'attack_on': 'D-H with PSK-HMAC Defense',
        'parameters': {'p': p, 'g': g},
        'keys': {},
        'events': [],
        'result': {}
    }

    try:
        # --- 客户端 (Alice) ---
        print("--- Alice ---")
        client_private, client_public = generate_key_pair(p, g)
        client_mac = generate_mac(PSK_ALICE_BOB, client_public)
        print(f"Alice 生成公钥: {client_public}")
        print(f"Alice 生成MAC: {client_mac.hex()[:10]}...")
        attack_log['keys']['client_public'] = client_public
        
        # --- 攻击者拦截 (Alice -> Bob) ---
        print("\n--- Attacker (拦截 Alice -> Bob) ---")
        forged_public_to_server, forged_mac_to_server = attacker.intercept_and_forge(
            client_public, client_mac, 'Client'
        )
        attack_log['events'].append({
            'type': 'intercept_client_to_server',
            'original_pub': client_public,
            'forged_pub': forged_public_to_server,
            'forged_mac_hex': forged_mac_to_server.hex()
        })

        # --- 服务器 (Bob) ---
        print("\n--- Bob (接收) ---")
        print(f"Bob 收到公钥: {forged_public_to_server}")
        print(f"Bob 收到MAC: {forged_mac_to_server.hex()[:10]}...")
        
        # Bob进行HMAC验证 
        is_valid_from_client = verify_mac(
            PSK_ALICE_BOB, 
            forged_public_to_server, # (这是攻击者的公钥)
            forged_mac_to_server     # (这是Alice的原始MAC)
        )
        
        print(f"Bob 验证MAC... 结果: {is_valid_from_client}")
        
        if not is_valid_from_client:
            # 防御成功！
            raise Exception("MITM ATTACK DETECTED! (Bob 验证 Alice 失败) 会话终止。")

        # (如果攻击未被检测到，Bob会继续)
        server_private, server_public = generate_key_pair(p, g)
        server_mac = generate_mac(PSK_ALICE_BOB, server_public)
        # ... 此处代码不会执行 ...

    except Exception as e:
        print(f"\n[系统日志] 错误: {e}")
        print("\n*** MITM 攻击被成功检测和阻止 ***")
        attack_log['result'] = {
            'status': 'Failed (Detected)',
            'reason': str(e)
        }

    # 保存结果文件
    result_filename = "dh_defense_attack_results.json"
    with open(result_filename, 'w') as f:
        json.dump(attack_log, f, indent=2)
    print(f"\n攻击结果已记录到: {result_filename}")
    
    return attack_log

if __name__ == "__main__":
    # 运行你的Week 3任务
    run_attack_on_defended_dh()
