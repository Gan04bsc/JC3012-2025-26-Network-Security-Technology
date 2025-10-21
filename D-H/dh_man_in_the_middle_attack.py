import random
import time
import json
from typing import Dict, Tuple, List
from datetime import datetime

def is_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin素数检测算法"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    if n in small_primes:
        return True
    for prime in small_primes:
        if n % prime == 0:
            return False
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int = 64) -> int:
    """生成指定位数的素数"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def generate_dh_parameters() -> Tuple[int, int]:
    """生成DH参数 - 使用标准测试参数确保正确性"""
    # 使用标准DH测试参数确保演示正确
    p = 23  # 标准测试素数
    g = 5   # 标准测试本原根
    return p, g

def generate_key_pair(p: int, g: int) -> Tuple[int, int]:
    """生成DH密钥对"""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(other_public_key: int, private_key: int, p: int) -> int:
    """计算共享密钥"""
    return pow(other_public_key, private_key, p)

class MITMAttacker:
    """正确的中间人攻击实现"""
    
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        # 攻击者只使用一对密钥来冒充双方
        self.attacker_private, self.attacker_public = generate_key_pair(p, g)
        self.shared_with_client = None
        self.shared_with_server = None
        self.intercepted_messages = []
    
    def intercept_client_to_server(self, client_public: int) -> int:
        """拦截客户端发往服务器的消息，返回攻击者公钥"""
        self.intercepted_messages.append({
            'type': 'client_public_key',
            'original': client_public,
            'forged': self.attacker_public,
            'timestamp': datetime.now().isoformat()
        })
        # 计算攻击者与客户端的共享密钥
        self.shared_with_client = compute_shared_secret(client_public, self.attacker_private, self.p)
        return self.attacker_public
    
    def intercept_server_to_client(self, server_public: int) -> int:
        """拦截服务器发往客户端的消息，返回攻击者公钥"""
        self.intercepted_messages.append({
            'type': 'server_public_key', 
            'original': server_public,
            'forged': self.attacker_public,
            'timestamp': datetime.now().isoformat()
        })
        # 计算攻击者与服务器的共享密钥
        self.shared_with_server = compute_shared_secret(server_public, self.attacker_private, self.p)
        return self.attacker_public

class AttackResultRecorder:
    """攻击结果记录器"""
    
    def __init__(self):
        self.results = {
            'attack_timestamp': datetime.now().isoformat(),
            'parameters': {},
            'keys': {},
            'shared_secrets': {},
            'attack_analysis': {},
            'intercepted_data': []
        }
    
    def record_parameters(self, p: int, g: int):
        """记录DH参数"""
        self.results['parameters'] = {
            'prime_modulus': p,
            'primitive_root': g
        }
    
    def record_keys(self, client_priv: int, client_pub: int, server_priv: int, server_pub: int, attacker_priv: int, attacker_pub: int):
        """记录各方密钥"""
        self.results['keys'] = {
            'client_private': client_priv,
            'client_public': client_pub,
            'server_private': server_priv, 
            'server_public': server_pub,
            'attacker_private': attacker_priv,
            'attacker_public': attacker_pub
        }
    
    def record_shared_secrets(self, client_shared: int, server_shared: int, attacker_client_shared: int, attacker_server_shared: int):
        """记录共享密钥"""
        self.results['shared_secrets'] = {
            'client_computed': client_shared,
            'server_computed': server_shared,
            'attacker_with_client': attacker_client_shared,
            'attacker_with_server': attacker_server_shared
        }
    
    def record_analysis(self, attack_successful: bool, details: Dict):
        """记录攻击分析结果"""
        self.results['attack_analysis'] = {
            'successful': attack_successful,
            'details': details
        }
    
    def record_intercepted_data(self, intercepted_data: List):
        """记录拦截的数据"""
        self.results['intercepted_data'] = intercepted_data
    
    def save_to_file(self, filename: str = "mitm_attack_results.json"):
        """保存结果到JSON文件"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Attack results saved to {filename}")
    
    def print_summary(self):
        """打印攻击结果摘要"""
        print("\n" + "="*60)
        print("ATTACK RESULTS SUMMARY")
        print("="*60)
        
        print(f"\nParameters:")
        print(f"  Prime modulus p: {self.results['parameters']['prime_modulus']}")
        print(f"  Primitive root g: {self.results['parameters']['primitive_root']}")
        
        print(f"\nPublic Keys:")
        print(f"  Client: {self.results['keys']['client_public']}")
        print(f"  Server: {self.results['keys']['server_public']}")
        print(f"  Attacker: {self.results['keys']['attacker_public']}")
        
        print(f"\nShared Secrets:")
        print(f"  Client computed: {self.results['shared_secrets']['client_computed']}")
        print(f"  Server computed: {self.results['shared_secrets']['server_computed']}")
        print(f"  Attacker-Client: {self.results['shared_secrets']['attacker_with_client']}")
        print(f"  Attacker-Server: {self.results['shared_secrets']['attacker_with_server']}")
        
        print(f"\nAttack Analysis:")
        success = self.results['attack_analysis']['successful']
        print(f"  Successful: {'YES' if success else 'NO'}")
        if success:
            print("  Impact: Attacker can decrypt both sides of communication")
            print("  Security: Client-server direct communication compromised")
        else:
            print("  Impact: Attack failed, secure communication maintained")

def demonstrate_correct_mitm_attack():
    """演示正确的中间人攻击"""
    recorder = AttackResultRecorder()
    
    print("="*60)
    print("CORRECT MITM ATTACK DEMONSTRATION")
    print("="*60)
    
    # 使用标准DH参数确保正确性
    p, g = generate_dh_parameters()
    recorder.record_parameters(p, g)
    
    print(f"\nDH Parameters:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    
    # 初始化攻击者
    attacker = MITMAttacker(p, g)
    
    # 客户端和服务器生成密钥对
    client_private, client_public = generate_key_pair(p, g)
    server_private, server_public = generate_key_pair(p, g)
    
    recorder.record_keys(client_private, client_public, server_private, server_public,
                        attacker.attacker_private, attacker.attacker_public)
    
    print(f"\nKey Generation:")
    print(f"  Client: private={client_private}, public={client_public}")
    print(f"  Server: private={server_private}, public={server_public}")
    print(f"  Attacker: private={attacker.attacker_private}, public={attacker.attacker_public}")
    
    print(f"\nMITM Attack Execution:")
    
    # 攻击过程
    forged_to_server = attacker.intercept_client_to_server(client_public)
    print(f"  Attacker intercepts client public key {client_public}")
    print(f"  Attacker sends forged public key {forged_to_server} to server")
    
    forged_to_client = attacker.intercept_server_to_client(server_public)
    print(f"  Attacker intercepts server public key {server_public}")
    print(f"  Attacker sends forged public key {forged_to_client} to client")
    
    # 计算共享密钥
    client_shared = compute_shared_secret(forged_to_client, client_private, p)
    server_shared = compute_shared_secret(forged_to_server, server_private, p)
    attacker_client_shared = attacker.shared_with_client
    attacker_server_shared = attacker.shared_with_server
    
    recorder.record_shared_secrets(client_shared, server_shared, attacker_client_shared, attacker_server_shared)
    
    print(f"\nShared Secret Computation:")
    print(f"  Client computes: g^{client_private} mod p = {client_shared}")
    print(f"  Server computes: g^{server_private} mod p = {server_shared}")
    print(f"  Attacker with client: g^{attacker.attacker_private} mod p = {attacker_client_shared}")
    print(f"  Attacker with server: g^{attacker.attacker_private} mod p = {attacker_server_shared}")
    
    # 攻击结果分析
    client_attacker_match = (client_shared == attacker_client_shared)
    server_attacker_match = (server_shared == attacker_server_shared)
    client_server_match = (client_shared == server_shared)
    
    attack_successful = (client_attacker_match and server_attacker_match and not client_server_match)
    
    analysis_details = {
        'client_attacker_key_match': client_attacker_match,
        'server_attacker_key_match': server_attacker_match,
        'client_server_key_match': client_server_match,
        'attacker_can_eavesdrop': client_attacker_match and server_attacker_match,
        'secure_channel_broken': not client_server_match
    }
    
    recorder.record_analysis(attack_successful, analysis_details)
    recorder.record_intercepted_data(attacker.intercepted_messages)
    
    print(f"\nSecurity Analysis:")
    print(f"  Client-Attacker shared secret match: {client_attacker_match}")
    print(f"  Server-Attacker shared secret match: {server_attacker_match}")
    print(f"  Client-Server shared secret match: {client_server_match}")
    
    if attack_successful:
        print(f"\n*** MITM ATTACK SUCCESSFUL ***")
        print(f"  - Attacker established shared secrets with both parties")
        print(f"  - Client and server have different shared secrets")
        print(f"  - Attacker can decrypt all communication")
    else:
        print(f"\n*** MITM ATTACK FAILED ***")
        print(f"  - Secure channel between client and server maintained")
    
    # 保存结果
    recorder.save_to_file()
    recorder.print_summary()
    
    return recorder.results

def run_multiple_attack_trials(num_trials: int = 5):
    """运行多次攻击试验以收集统计数据"""
    print("\n" + "="*60)
    print(f"RUNNING {num_trials} ATTACK TRIALS FOR STATISTICS")
    print("="*60)
    
    results = []
    successful_attacks = 0
    
    for i in range(num_trials):
        print(f"\nTrial {i+1}:")
        trial_result = demonstrate_correct_mitm_attack()
        results.append(trial_result)
        
        if trial_result['attack_analysis']['successful']:
            successful_attacks += 1
        
        # 短暂暂停
        time.sleep(1)
    
    # 统计摘要
    print("\n" + "="*60)
    print("ATTACK TRIALS SUMMARY")
    print("="*60)
    print(f"Total trials: {num_trials}")
    print(f"Successful attacks: {successful_attacks}")
    print(f"Success rate: {(successful_attacks/num_trials)*100:.1f}%")
    print(f"Vulnerability confirmed: {'YES' if successful_attacks > 0 else 'NO'}")

if __name__ == "__main__":
    # 运行单次攻击演示
    attack_results = demonstrate_correct_mitm_attack()
    
    print("\n" + "="*70)
    input("Press Enter to run multiple trials for statistical analysis...")
    
    # 运行多次试验收集数据
    run_multiple_attack_trials(3)