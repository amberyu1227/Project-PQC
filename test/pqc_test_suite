"""
PQC Migration & Security Rule Test Suite
此檔案包含刻意設計的不安全代碼與 PQC 特徵，
僅用於測試靜態代碼分析規則 (SAST) 的觸發準確度。
"""

import hashlib
import random
import os
# 假設環境中使用 PyCryptodome，掃描器應能識別這些庫的引用
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.KDF import PBKDF2

# ==========================================
# 1. 弱雜湊算法 (Weak Hashing)
# ==========================================
def test_weak_hashes():
    data = b"Sensitive Data"
    
    # [B303] WEAK_HASH_SHA1
    # 預期觸發：使用了 SHA1
    sha1_hash = hashlib.sha1(data).hexdigest()
    
    # [B324] WEAK_HASH_MD5
    # 預期觸發：使用了 MD5
    md5_hash = hashlib.md5(data).hexdigest()
    
    print(f"Hashes: {sha1_hash}, {md5_hash}")

# ==========================================
# 2. 弱加密算法 (Weak Ciphers)
# ==========================================
def test_weak_ciphers():
    key_des = b'8bytekey'
    
    # [B304] WEAK_CIPHER_DES (DES/3DES)
    # 預期觸發：使用了 DES 或 3DES
    cipher_des = DES.new(key_des, DES.MODE_ECB)
    cipher_3des = DES3.new(b'16bytekey16bytek', DES3.MODE_ECB)

# ==========================================
# 3. PQC 遷移目標與 AES 使用樣式
# ==========================================
def test_pqc_targets_and_aes():
    # [B413_AES_WEAK] AES ECB Mode
    # 預期觸發：使用了 ECB 模式
    key = b'1234567890123456' # 16 bytes
    cipher_weak = AES.new(key, AES.MODE_ECB)

    # [B413_AES_SAFE] AES GCM (PQC Safe Asset)
    # [B416] RISKY_GCM_NONCE_LENGTH (Trigger: 16 bytes instead of 12)
    # 預期觸發：GCM Nonce 長度風險
    bad_nonce = os.urandom(16) 
    cipher_safe = AES.new(key, AES.MODE_GCM, nonce=bad_nonce)

    # [B413_IV_WEAK] CBC Mode with static IV
    # 預期觸發：IV/Nonce 風險 (硬編碼或未隨機化)
    static_iv = b'0000000000000000'
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=static_iv)

# ==========================================
# 4. 非對稱加密 (RSA/ECC) - PQC 核心目標
# ==========================================
def test_asymmetric_crypto():
    # [B413_RSA_WEAK_SIZE] RSA < 2048
    # 預期觸發：RSA 金鑰長度不足
    weak_rsa_key = RSA.generate(1024)
    
    # [B413_RSA] RSA Key Generation (General PQC Target)
    # 預期觸發：RSA 生成 (PQC 遷移對象)
    strong_rsa_key = RSA.generate(2048)

    # [B413_ECC] ECC Usage
    # [B415_ECC_WEAK_CURVE] P-192 is considered weak
    # 預期觸發：弱橢圓曲線 P-192 + ECC 使用偵測
    weak_ecc = ECC.generate(curve='P-192')
    normal_ecc = ECC.generate(curve='P-256')

# ==========================================
# 5. PQC 正面識別 (PQC Ready)
# ==========================================
def test_pqc_ready_libs():
    """
    模擬 PQC 函式庫調用，測試是否能識別 Kyber/Dilithium
    """
    # [B501_KYBER] 模擬 Kyber (ML-KEM)
    # 掃描器應偵測字串或函數名中的 "Kyber"
    kem_algo = "Kyber-768" 
    print(f"Initializing PQC KEM: {kem_algo}")

    # [B502_DILITHIUM] 模擬 Dilithium (ML-DSA)
    # 掃描器應偵測字串或函數名中的 "Dilithium"
    sign_algo = "Dilithium3"
    print(f"Signing with {sign_algo}...")

# ==========================================
# 6. [HARDCORE] 硬編碼與機密管理
# ==========================================
def test_hardcoded_secrets():
    # [B702_HARDCODED_KEY] Generic Hardcoded Key
    # [B105_HARDCODED_SECRET] Secret Leakage
    # 預期觸發：變數名含 Key/Secret 且有硬編碼值
    secret_key = "x8s#9@2!super_secret_key_value"
    
    # [B706_HARDCODED_PASSWORD]
    # 預期觸發：變數名含 Password
    db_password = "Password123!"
    
    # [B707_HARDCODED_AWS] AWS Access Key ID Pattern
    # 預期觸發：AKIA 開頭的字串
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    
    # [B708_HARDCODED_TOKEN]
    # 預期觸發：Token 變數或 JWT 格式字串
    api_token = "eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"

    # [B709_HARDCODED_PQC_SK] PQC Private Key Pattern
    # 預期觸發：PQC 私鑰硬編碼
    pqc_private_key = b'\x00\x01\x02...simulate_kyber_sk...'

# ==========================================
# 7. 隨機數與進階參數檢查
# ==========================================
def test_advanced_params():
    # [B701_WEAK_RNG] 使用 random 模組
    # 預期觸發：使用弱隨機源
    weak_rand = random.random()
    
    password = b"user_password"
    
    # [B710_SHORT_SALT] Salt < 16 bytes
    # 預期觸發：Salt 長度不足
    salt = b"12345" 
    
    # [B703_WEAK_KDF_ITERATIONS] Iterations < 600,000
    # 預期觸發：KDF 迭代次數過低
    derived_key = hashlib.pbkdf2_hmac('sha256', password, salt, 1000)

if __name__ == "__main__":
    print("PQC Rule Test Suite Running...")
