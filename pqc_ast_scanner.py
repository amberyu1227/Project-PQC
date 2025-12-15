import ast
import sys
import os
import javalang          # 需要安裝: pip install javalang
import pycparser         # 需要安裝: pip install pycparser
from pycparser import c_parser, c_ast, parse_file
import pandas as pd             # 數據處理
import plotly.graph_objects as go # 視覺化圖表
import json                     # JSON 輸出
from datetime import datetime # 獲取時間戳
import webbrowser

# --- PQC 知識庫與修復建議 (PQC_KNOWLEDGE_BASE) ---
PQC_KNOWLEDGE_BASE = {
    # 弱雜湊 (Priority Fixes)
    "B303": {"type": "WEAK_HASH_SHA1", "message": "使用了 SHA1 雜湊算法。", "fix": "替換為 hashlib.sha256/sha3，SHA1 對碰撞攻擊是脆弱的。"},
    "B324": {"type": "WEAK_HASH_MD5", "message": "使用了 MD5 雜湊算法。", "fix": "必須移除 MD5，替換為 SHA256。"},
    # 弱加密算法 (Priority Fixes)
    "B304": {"type": "WEAK_CIPHER_DES", "message": "使用了 DES/3DES 弱加密算法。", "fix": "停用 DES/3DES，改用 AES-256 GCM 模式。"},
    # 量子脆弱資產與使用樣式 (PQC/AES)
    "B413_RSA": {"type": "PQC_TARGET_RSA", "message": "發現 RSA 密鑰生成。", "fix": "量子脆弱：考慮替換為 CRYSTALS-Kyber (KEM) 或 Dilithium (Signature)。"},
    "B413_AES_WEAK": {"type": "WEAK_CIPHER_MODE", "message": "使用了不安全的 AES/ECB 模式。", "fix": "替換為 AES-256 GCM 或 CCM 模式，確保認證性。"},
    "B413_AES_SAFE": {"type": "TRADITIONAL_AES_ASSET", "message": "使用了 AES 加密資產。", "fix": "這是一個抗量子資產。請確保 IV/Nonce 是正確生成的。"},
    "B413_RSA_WEAK_SIZE": {
        "type": "WEAK_ASSET_RSA", 
        "message": "發現 RSA 密鑰長度小於 2048 bits，對暴力破解脆弱。", 
        "fix": "將密鑰長度至少增加到 2048/4096 bits，並規劃 PQC 遷移。"
    },
    # CBC/CFB 模式 IV 缺失 (使用樣式風險)
    "B413_IV_WEAK": {
        "type": "WEAK_IV_NONCE", 
        "message": "在 CBC/CFB 模式中，未偵測到 IV/Nonce 參數，易受重放攻擊。", 
        "fix": "必須使用 os.urandom (Python) 或 SecureRandom (Java) 創建隨機 IV。"
    },
    # 量子脆弱的 ECC
    "B413_ECC": { 
        "type": "PQC_TARGET_ECC", 
        "message": "發現 ECC/ECDSA/ECDH 橢圓曲線加密資產。", 
        "fix": "核心量子脆弱資產，建議替換為 CRYSTALS-Dilithium/Falcon。"
    },
	# 硬編碼偵測
	"B105_HARDCODED_SECRET": {
    "type": "SECRET_LEAKAGE",
    "message": "發現硬編碼密鑰，可能導致密鑰洩露，影響 PQC 遷移後的安全性。",
    "fix": "將密鑰儲存於環境變數或專門的密鑰管理器中。"
	},
    # --- PQC 正面識別 (PQC Ready) ---
    "B501_KYBER": {"type": "PQC_KEM_ML_KEM", "message": "發現 NIST 標準 PQC 算法：ML-KEM (Kyber)。", "fix": "PQC READY。請確保實作符合 FIPS 203 標準。"},
    "B502_DILITHIUM": {"type": "PQC_SIGN_ML_DSA", "message": "發現 NIST 標準 PQC 算法：ML-DSA (Dilithium)。", "fix": "PQC READY。請確保實作符合 FIPS 204 標準。"},
    # --- [HARDCORE] 硬編碼與機密管理 ---
    "B702_HARDCODED_KEY": {"type": "HARDCODED_SECRET_KEY", "message": "偵測到疑似硬編碼的加密金鑰。", "fix": "絕對禁止在程式碼中寫死金鑰。請改用環境變數或 KMS。"},
    "B706_HARDCODED_PASSWORD": {"type": "HARDCODED_PASSWORD", "message": "偵測到疑似硬編碼的密碼。", "fix": "請勿將密碼儲存在原始碼中。"},
    "B707_HARDCODED_AWS": {"type": "HARDCODED_CLOUD_CREDENTIAL", "message": "偵測到硬編碼 AWS Key (AKIA...)。", "fix": "使用 IAM Role。"},
    "B708_HARDCODED_TOKEN": {"type": "HARDCODED_API_TOKEN", "message": "偵測到疑似硬編碼 API Token。", "fix": "動態生成 Token。"},
    "B709_HARDCODED_PQC_SK": {"type": "HARDCODED_PQC_PRIVATE_KEY", "message": "偵測到疑似 PQC 私鑰硬編碼。", "fix": "PQC 私鑰極為敏感。"},
    "B701_WEAK_RNG": {"type": "WEAK_RANDOM_SOURCE", "message": "使用弱亂數 (random)。", "fix": "改用 os.urandom。"},

    # --- [ADVANCE] 進階參數檢查 ---
    "B415_ECC_WEAK_CURVE": {"type": "WEAK_ECC_CURVE", "message": "弱橢圓曲線 (如 P-192)。", "fix": "使用 NIST P-256 以上。"},
    "B703_WEAK_KDF_ITERATIONS": {"type": "WEAK_KDF_ITERATION_COUNT", "message": "PBKDF2 迭代次數過低。", "fix": "建議 > 600,000 次。"},
    "B710_SHORT_SALT": {"type": "INSUFFICIENT_SALT_LENGTH", "message": "Salt 長度不足。", "fix": "Salt 應 > 16 bytes。"},
    "B416_GCM_NONCE_LENGTH": {"type": "RISKY_GCM_NONCE_LENGTH", "message": "GCM Nonce 非 12 bytes。", "fix": "固定為 12 bytes。"},
}
# ----------------------------------------


# --- 核心邏輯：報告生成 (作為獨立函數) ---
def report_finding(node, filename, line, rule_id, custom_message=None):
    info = PQC_KNOWLEDGE_BASE.get(rule_id, {"type": "UNKNOWN", "message": "未知規則", "fix": "N/A"})
    
    # 根據節點類型獲取代碼片段（適應 Python, Java, C）
    if isinstance(node, str):
        code_snippet = node
    elif isinstance(node, (ast.Call, ast.Attribute)):
        code_snippet = ast.unparse(node).strip()
    elif hasattr(node, 'value'):
        # 適用於 javalang 的 Literal 節點
        code_snippet = str(node.value).strip('"') 
    elif hasattr(node, 'name'):
        # 適用於 C AST (FuncCall)
        code_snippet = str(node.name) if isinstance(node, c_ast.FuncCall) else str(node)
    else:
        code_snippet = str(node)

    location_str = f"{filename}:{line}" if line > 0 else f"{filename}:N/A"

    return {
        "RuleID": rule_id,
        "Type": info.get('type', 'UNKNOWN_TYPE'),
        "Location": location_str,
        "CodeSnippet": code_snippet,
        "Message": custom_message if custom_message else info.get('message', 'N/A'),
        "FixSuggestion": info.get('fix', 'N/A')
    }

def _determine_pqc_status(rule_id):
    """決定資產的 PQC 狀態 (用於 CBOM)"""
    if "HARDCODED" in rule_id: return "CRITICAL_SECRET_LEAK"
    if any(k in rule_id for k in ["SHA1", "MD5", "DES"]): return "VULNERABLE (CLASSIC)"
    if any(k in rule_id for k in ["RSA", "ECC", "WEAK"]): return "VULNERABLE (QUANTUM)"
    if any(k in rule_id for k in ["KYBER", "DILITHIUM"]): return "PQC_READY"
    if "AES" in rule_id and "SAFE" in rule_id: return "SAFE (QUANTUM-RESISTANT)"
    return "UNKNOWN"

# --- Python 掃描核心 ---
class PQC_AST_Visitor(ast.NodeVisitor):
    def __init__(self, filename, findings_list):
        self.filename = filename
        self.findings_list = findings_list 

    def _get_literal_value(self, node):
        if isinstance(node, ast.Constant): return node.value
        return None

    def _get_call_arg_value(self, node, arg_index, kw_name):
        val = None
        for k in node.keywords:
            if k.arg == kw_name and isinstance(k.value, ast.Constant): val = k.value.value
        if val is None and len(node.args) > arg_index:
            if isinstance(node.args[arg_index], ast.Constant): val = node.args[arg_index].value
        return val

    def visit_Assign(self, node):
        target_name = ""
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
                break
        if not target_name:
            self.generic_visit(node)
            return

        # 獲取字面量值 (修正 UnboundLocalError)
        raw_value = self._get_literal_value(node.value)
        assigned_value = None 
        if isinstance(raw_value, str): assigned_value = raw_value
        elif isinstance(raw_value, bytes):
            try: assigned_value = raw_value.decode('utf-8')
            except: assigned_value = str(raw_value)

        # 檢查邏輯
        if assigned_value and len(assigned_value) > 8: 
            if assigned_value.startswith(("AKIA", "ASIA")):
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B707_HARDCODED_AWS"))
            elif any(s in target_name for s in ['password', 'passwd', 'pwd']) and "hash" not in target_name:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B706_HARDCODED_PASSWORD"))
            elif ("token" in target_name or "api_key" in target_name) and "csrf" not in target_name and len(assigned_value) > 10:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B708_HARDCODED_TOKEN"))
            elif ("sk" in target_name or "secret_key" in target_name) and ("pqc" in target_name or "kyber" in target_name):
                 self.findings_list.append(report_finding(node, self.filename, node.lineno, "B709_HARDCODED_PQC_SK"))
            elif any(s in target_name for s in ['key', 'secret', 'private']):
                if "public" not in target_name and "pub" not in target_name:
                    self.findings_list.append(report_finding(node, self.filename, node.lineno, "B702_HARDCODED_KEY"))
        self.generic_visit(node)# 確保繼續遍歷子節點

    def visit_Call(self, node):
        full_name = self._get_full_name(node.func)
        
        # 1. 弱雜湊 (最高優先級別)
        if "hashlib.sha1" in full_name:
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B303"))
        elif "hashlib.md5" in full_name: 
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B324"))
        elif "random.random" in full_name or "random.randint" in full_name:
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B701_WEAK_RNG"))   

        # 2. 量子脆弱/弱加密 (DES, RSA)
        elif any(x in full_name for x in ["DES.new", "DES3.new", "Crypto.Cipher.DES"]):
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B304"))
            
        elif "RSA.generate" in full_name:
            key_size = self._get_int_arg(node.args, 0)
            if key_size is not None and key_size < 2048:
                 self.findings_list.append(report_finding(node, self.filename, node.lineno, "B413_RSA_WEAK_SIZE"))
            else:
                 self.findings_list.append(report_finding(node, self.filename, node.lineno, "B413_RSA"))
                 
        # 3. AES 模式檢查 (修正邏輯，確保 ECB/IV 缺失優先被檢查)
        elif "AES.new" in full_name:
            is_ecb = self._is_ecb_mode(node)
            is_cbc_cfb = self._is_cbc_cfb_mode(node)
            iv_is_missing = not self._has_keyword_arg(node.keywords, 'iv')
            
            # 確保最危險的模式優先被標記 (ECB)
            if is_ecb: 
                finding = report_finding(node, self.filename, node.lineno, "B413_AES_WEAK") 
            # 其次檢查 IV 缺失 (使用樣式漏洞)
            elif is_cbc_cfb and iv_is_missing: 
                 finding = report_finding(node, self.filename, node.lineno, "B413_IV_WEAK") 
            # 最後，如果通過所有漏洞檢查，則視為安全資產
            else:
                 finding = report_finding(node, self.filename, node.lineno, "B413_AES_SAFE") 
            
            self.findings_list.append(finding)

        if node.args or node.keywords:
            args_str = ""
            try:
                # 將所有參數轉為字串以進行關鍵字搜索
                args_str = ", ".join([ast.unparse(a) for a in node.args])
                args_str += ", ".join([ast.unparse(k.value) for k in node.keywords])
            except: pass
            
            args_str = args_str.upper()
            if "KYBER" in args_str or "ML-KEM" in args_str:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B501_KYBER"))
            elif "DILITHIUM" in args_str or "ML-DSA" in args_str:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B502_DILITHIUM")) 

        if "PBKDF2" in full_name:
            iters = self._get_call_arg_value(node, 3, 'iterations')
            if iters is not None and isinstance(iters, int) and iters < 600000:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B703_WEAK_KDF_ITERATIONS"))
        
        if "generate_private_key" in full_name and "ec" in full_name:
            for k in node.keywords:
                if k.arg == 'curve':
                    val = ast.unparse(k.value).upper() if hasattr(ast, 'unparse') else ""
                    if any(w in val for w in ['SECP192', 'SECT163', 'BRAINPOOLP160']):
                        self.findings_list.append(report_finding(node, self.filename, node.lineno, "B415_ECC_WEAK_CURVE"))

        elif "ECC.generate" in full_name:
            is_weak_curve = False
            for k in node.keywords:
                # 檢查 curve='P-192' 等弱曲線
                if k.arg == 'curve':
                    val = ast.unparse(k.value).upper() if hasattr(ast, 'unparse') else ""
                    if any(w in val for w in ['P-192', 'SECP192', 'BRAINPOOLP160']):
                        self.findings_list.append(report_finding(node, self.filename, node.lineno, "B415_ECC_WEAK_CURVE"))
                        is_weak_curve = True
            
            # 如果不是弱曲線，它仍然是 PQC 遷移目標 (ECC 本身對量子脆弱)
            if not is_weak_curve:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B413_ECC"))

        # --- [B710] Salt 長度檢查 (針對 os.urandom) ---
        # 檢查: os.urandom(N) 其中 N < 16
        if "os.urandom" in full_name:
            size = self._get_int_arg(node.args, 0)
            # 排除 12 (GCM Nonce 標準長度)，只針對過短的 Salt/IV
            if size is not None and size < 16 and size != 12:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B710_SHORT_SALT"))

        # --- [B416] AES-GCM Nonce 長度檢查 ---
        # 檢查: AES.new(..., nonce=os.urandom(N)) 其中 N != 12
        if "AES.new" in full_name:
            # 檢查是否使用了 GCM 模式
            is_gcm = False
            for k in node.keywords:
                if k.arg == 'mode' and 'GCM' in ast.unparse(k.value).upper():
                    is_gcm = True
                    break
            
            # 如果是 GCM，檢查 nonce 參數
            if is_gcm:
                for k in node.keywords:
                    if k.arg == 'nonce':
                        # 檢查 nonce 是否來自 os.urandom
                        if isinstance(k.value, ast.Call) and "urandom" in ast.unparse(k.value.func):
                             nonce_size = self._get_int_arg(k.value.args, 0)
                             if nonce_size is not None and nonce_size != 12:
                                  self.findings_list.append(report_finding(node, self.filename, node.lineno, "B416_GCM_NONCE_LENGTH"))

        # 確保繼續遍歷子節點
        self.generic_visit(node)

    # 辅助函数: 获取完整函数名
    def _get_full_name(self, node):
        if isinstance(node, ast.Attribute):
            return self._get_full_name(node.value) + "." + node.attr
        elif isinstance(node, ast.Name):
            return node.id
        return ""
    
    # 辅助函数: 检查 ECB 模式
    def _is_ecb_mode(self, call_node):
        for keyword in call_node.keywords:
            if keyword.arg == 'mode':
                return 'ECB' in ast.unparse(keyword.value).upper()
        # 檢查第二個位置參數
        if len(call_node.args) > 1:
            return 'ECB' in ast.unparse(call_node.args[1]).upper()
        return False
    
    # 辅助函数: 检查 CBC/CFB 模式 (需要 IV)
    def _is_cbc_cfb_mode(self, call_node):
        for keyword in call_node.keywords:
            if keyword.arg == 'mode':
                mode = ast.unparse(keyword.value).upper()
                return 'CBC' in mode or 'CFB' in mode
        # 檢查第二個位置參數
        if len(call_node.args) > 1:
            mode = ast.unparse(call_node.args[1]).upper()
            return 'CBC' in mode or 'CFB' in mode
        return False
    
    # 辅助函数: 检查关键字参数是否存在
    def _has_keyword_arg(self, keywords, arg_name):
        return any(keyword.arg == arg_name for keyword in keywords)
        
    # 辅助函数: 获取整数参数 (Key Size)
    def _get_int_arg(self, args, index):
        if len(args) > index:
            arg = args[index]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                return arg.value
        return None

    def visit_Constant(self, node):
        """
        捕捉所有字串常數，用於識別 PQC 關鍵字 (Kyber, Dilithium)
        適用於 Python 3.8+ (舊版 Python 使用 visit_Str)
        """
        if isinstance(node.value, str):
            val = node.value.upper()
            # 檢查 PQC 關鍵字
            if "KYBER" in val or "ML-KEM" in val:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B501_KYBER"))
            elif "DILITHIUM" in val or "ML-DSA" in val:
                self.findings_list.append(report_finding(node, self.filename, node.lineno, "B502_DILITHIUM"))
        
        # 繼續遍歷 (雖然 Constant 通常是葉節點)
        self.generic_visit(node)
        
def scan_python(filepath):
    findings_list = []
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath) 
    visitor = PQC_AST_Visitor(filepath, findings_list)
    visitor.visit(tree)
    return findings_list


# --- Java 掃描核心 ---

def is_secret_var(name):
    """ 判斷變數名稱是否敏感 """
    sensitive = ['key', 'secret', 'password', 'passwd', 'pwd', 'token', 'private', 'credential']
    name = name.lower()
    return any(k in name for k in sensitive) and "public" not in name and "hash" not in name

def scan_java(filepath):
    findings_list = []
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()

    try:
        # javalang 解析器
        tree = javalang.parse.parse(code) 
        
    except javalang.tokenizer.LexerError as e:
        # 捕獲詞法錯誤 (例如非法字符)，返回錯誤資訊
        print(f"❌ Java Lexer Error (可能為非法字符或 BOM): {e}")
        return []
    except javalang.parser.ParserError as e:
        # 捕獲語法錯誤 (例如缺少分號或類別名錯誤)
        print(f"❌ Java Parser Error (語法錯誤或結構不完整): {e}")
        return []
    except Exception as e:
        # 捕獲其他所有錯誤
        print(f"❌ Java AST 錯誤: {e}")
        return []

    # --- 成功解析後，開始遍歷 AST ---
    for path, node in tree:
        try:
            # 確保 node 是一個 javalang AST 節點， path 是節點路徑
            if not isinstance(node, javalang.tree.Node):
                continue
        except ValueError:
            # 捕獲 too many values to unpack 錯誤
            # 這表示 javalang 返回的不是 (path, node) 格式
            continue
        
        line_num = node.position.line if node.position else 0

        # 如果行號為 0 (缺失)，嘗試從路徑中回溯到最近的父節點
        if line_num == 0:
            # 關鍵修正：將 path 迭代包裹在 try-except 塊中，以防 path 內部結構不穩定
            try:
                for p_item in reversed(path):
                    # p_item 應該是 (attribute_name, p_node)
                    if len(p_item) == 2:
                        p_node = p_item[1]
                        if p_node.position:
                            line_num = p_node.position.line
                            break
            except Exception:
                # 捕獲 path 迭代時的解包錯誤
                pass
        
        # 排除掉頂層的 PackageDeclaration 或 Import 語句
        if line_num == 0 and isinstance(node, (javalang.tree.PackageDeclaration, javalang.tree.Import)):
            continue
        
        
        # 1. 方法呼叫檢查 (MethodInvocation)
        if isinstance(node, javalang.tree.MethodInvocation):
            
            # [getInstance 檢查]
            if node.member == 'getInstance':
                if node.arguments and isinstance(node.arguments[0], javalang.tree.Literal):
                    arg_value = node.arguments[0].value.strip('"').upper()
                    
                    # === 構造清晰的代碼片段 (getInstance) ===
                    qualifier = node.qualifier if node.qualifier else "Cipher/Digest"
                    readable_snippet = f"{qualifier}.getInstance(\"{node.arguments[0].value.strip('\"')}\")"
                    
                    # 規則匹配 (使用 readable_snippet)
                    if "SHA1" in arg_value or "SHA-1" in arg_value:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B303"))
                    elif "MD5" in arg_value:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B324"))
                    elif "DES" in arg_value or "DESEDE" in arg_value:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B304")) 
                    elif "AES" in arg_value:
                        if "ECB" in arg_value:
                            findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_AES_WEAK")) 
                        else:
                            findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_AES_SAFE"))
                    elif "RSA" in arg_value:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_RSA"))
                    elif "EC" in arg_value or "ECDSA" in arg_value or "ECDH" in arg_value:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_ECC"))

            # [initialize 檢查]
            elif node.member == 'initialize':
                if len(node.arguments) == 1 and isinstance(node.arguments[0], javalang.tree.Literal):
                    try:
                        key_size = int(node.arguments[0].value)
                        readable_snippet = f"keyPairGenerator.initialize({key_size})" 
                        
                        if key_size < 2048:
                            findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_RSA_WEAK_SIZE", f"RSA 金鑰過短 ({key_size})"))
                        else:
                            findings_list.append(report_finding(readable_snippet, filepath, line_num, "B413_RSA", "RSA 金鑰生成 (PQC 目標)"))
                    except ValueError:
                        pass
            
            # [弱亂數 nextInt/nextBytes 檢查]
            elif node.member == 'nextInt' or node.member == 'nextBytes':
                if hasattr(node, 'qualifier') and node.qualifier and 'rand' in node.qualifier.lower() and 'secure' not in node.qualifier.lower():
                    readable_snippet = f"{node.qualifier}.{node.member}(...)"
                    findings_list.append(report_finding(readable_snippet, filepath, line_num, "B701_WEAK_RNG"))
        # 2. 變數宣告檢查 (LocalVariableDeclaration) - 硬編碼機密
        elif isinstance(node, javalang.tree.LocalVariableDeclaration):
            for declarator in node.declarators:
                var_name = declarator.name.lower()

                # [硬編碼機密檢查]
                if declarator.initializer and isinstance(declarator.initializer, javalang.tree.Literal):
                    raw_value = str(declarator.initializer.value)
                    
                    if raw_value.startswith('"'):
                        value = raw_value.strip('"')
                        # === 構造硬編碼密鑰片段 ===
                        readable_snippet = f"{declarator.name} = \"{value[:15]}...\""
                        
                        if value.startswith("AKIA") or value.startswith("ASIA"):
                            findings_list.append(report_finding(readable_snippet, filepath, line_num, "B707_HARDCODED_AWS"))
                        elif is_secret_var(var_name):
                            if "password" in var_name:
                                findings_list.append(report_finding(readable_snippet, filepath, line_num, "B706_HARDCODED_PASSWORD"))
                            elif "token" in var_name:
                                findings_list.append(report_finding(readable_snippet, filepath, line_num, "B708_HARDCODED_TOKEN"))
                            elif "pqc" in var_name or "kyber" in var_name:
                                findings_list.append(report_finding(readable_snippet, filepath, line_num, "B709_HARDCODED_PQC_SK"))
                            else:
                                findings_list.append(report_finding(readable_snippet, filepath, line_num, "B702_HARDCODED_KEY"))
                
                # [Salt 長度檢查]
                if 'salt' in var_name and declarator.initializer:
                    init = declarator.initializer
                    readable_snippet = f"byte[] {declarator.name} = new byte[...]"
                    salt_size = None
                        
                    if isinstance(init, javalang.tree.ArrayCreator) and init.dimensions and init.dimensions[0].value.isdigit():
                        salt_size = int(init.dimensions[0].value)
                    elif isinstance(init, javalang.tree.ArrayInitializer):
                        if init.initializers: salt_size = len(init.initializers)
                        
                    if salt_size is not None and salt_size < 16:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B710_SHORT_SALT"))

        # 3. 類別創建檢查 (ClassCreator)
        elif isinstance(node, javalang.tree.ClassCreator):
            type_name = node.type.name
            
            # [弱亂數]
            if type_name == 'Random':
                 readable_snippet = "new Random()"
                 findings_list.append(report_finding(readable_snippet, filepath, line_num, "B701_WEAK_RNG"))

            # [PBKDF2 迭代次數]
            elif "PBEKeySpec" in type_name and len(node.arguments) >= 3:
                iter_arg = node.arguments[2]
                if isinstance(iter_arg, javalang.tree.Literal) and iter_arg.value.isdigit():
                    iterations = int(iter_arg.value)
                    if iterations < 600000:
                        readable_snippet = f"new {type_name}(..., {iterations}, ...)"
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B703_WEAK_KDF_ITERATIONS"))

            # [ECC 曲線檢查]
            elif "ECGenParameterSpec" in type_name and len(node.arguments) > 0:
                curve_arg = node.arguments[0]
                if isinstance(curve_arg, javalang.tree.Literal):
                    curve_name = curve_arg.value.strip('"').upper()
                    readable_snippet = f"new {type_name}(\"{curve_name}\")"
                    
                    if any(w in curve_name for w in ['SECP192', 'SECT163', 'BRAINPOOLP160']):
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B415_ECC_WEAK_CURVE"))

            # [GCM Nonce 長度檢查]
            elif "GCMParameterSpec" in type_name and len(node.arguments) >= 2:
                iv_arg = node.arguments[1]
                readable_snippet = f"new GCMParameterSpec(...)"
                if isinstance(iv_arg, javalang.tree.ArrayCreator):
                    for dim in iv_arg.dimensions:
                        if isinstance(dim, javalang.tree.Literal) and dim.value.isdigit():
                            size = int(dim.value)
                            if size != 12:
                                findings_list.append(report_finding(readable_snippet, filepath, line_num, "B416_GCM_NONCE_LENGTH"))
        
        # 4. 字串常數檢查 (PQC 識別)
        elif isinstance(node, javalang.tree.Literal):
            val = str(node.value)
            if val.startswith('"'):
                val_clean = val.strip('"').upper()
                if "KYBER" in val_clean or "ML-KEM" in val_clean or "DILITHIUM" in val_clean or "ML-DSA" in val_clean:
                    readable_snippet = f"\"{val_clean}\""
                    if "KYBER" in val_clean or "ML-KEM" in val_clean:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B501_KYBER"))
                    elif "DILITHIUM" in val_clean or "ML-DSA" in val_clean:
                        findings_list.append(report_finding(readable_snippet, filepath, line_num, "B502_DILITHIUM"))

    return findings_list

# --- C/C++ 掃描核心 ---
def scan_c_cpp(filepath):
    print(f"C/C++ 掃描邏輯尚未實作。")
    return []


# --- 主控函數 ---
def scan_project_recursive(root_dir):
    all_findings = []
    SUPPORTED_EXTENSIONS = ('.py', '.java', '.c', '.cpp')

    for dirpath, dirnames, filenames in os.walk(root_dir):
        if 'pqc_venv' in dirpath or '.git' in dirpath: # 忽略虚拟环境和 Git 目录
            continue
            
        for filename in filenames:
            if filename.endswith(SUPPORTED_EXTENSIONS):
                filepath = os.path.join(dirpath, filename)
                print(f"掃描檔案: {filepath}")
                
                try:
                    findings = scan_file(filepath)
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"❌ 檔案 {filepath} 掃描失敗: {e}")
                    
    return all_findings


def scan_file(filepath):
    if filepath.endswith(".py"):
        return scan_python(filepath)
    elif filepath.endswith(".java"):
        return scan_java(filepath)
    elif filepath.endswith(".c") or filepath.endswith(".cpp"):
        return scan_c_cpp(filepath)
    else:
        return []


# -----------------------------------------------------------------
# CBOM 視覺化和报告生成模塊
# -----------------------------------------------------------------

def generate_cbom_json(findings):
    """
    將掃描結果轉換為簡化的 CBOM (Cryptographic Bill of Materials) 格式。
    """
    cbom_data = {
        "metadata": {
            "tool": "PQC Hybrid Auditor",
            "version": "1.0",
            "total_findings": len(findings),
            "timestamp": datetime.now().isoformat()
        },
        "cryptographic_assets": []
    }
    
    for finding in findings:
        # 根據 RuleID 判斷資產類型 (簡化)
        asset_type = "ASYMMETRIC_PQC" if 'RSA' in finding['RuleID'] or 'ECC' in finding['RuleID'] else "SYMMETRIC_HASH_ETC"
        
        cbom_data['cryptographic_assets'].append({
            "asset_id": finding['RuleID'],
            "location": finding['Location'],
            "type": asset_type,
            "code_snippet": finding['CodeSnippet'],
            "risk_status": finding['Type'],
        })
        
    return cbom_data

def generate_risk_pie_chart(findings):
    """
    使用 Plotly 生成風險分佈圓餅圖 (Pie Chart)，並輸出 HTML 字符串。
    """
    if not findings:
        return "<h3>未發現加密資產或弱點。</h3>"
        
    df = pd.DataFrame(findings)
    #risk_counts = df['Type'].value_counts()
    
    # 定義顏色：確保高風險 (WEAK, SECRET) 使用紅色/橙色
    color_map = {
        'WEAK_HASH_SHA1': '#D35400',       # 🟠 深焦橙 (高風險)
        'WEAK_HASH_MD5': '#C0392B',        # 🔴 深磚紅 (Critical)
        'WEAK_CIPHER_DES': '#C0392B',      # 🔴 深磚紅 (Critical)
        'WEAK_ASSET_RSA': '#D35400',       # 🟠 深焦橙 (高風險)
        'WEAK_CIPHER_MODE': '#C0392B',     # 🔴 深磚紅 (Critical)
        'WEAK_IV_NONCE': '#D35400',        # 🟠 深焦橙 (高風險)
        'PQC_TARGET_RSA': '#2980B9',       # 🔵 深海藍 (PQC 核心目標)
        'PQC_TARGET_ECC': '#2980B9',       # 🔵 深海藍 (PQC 核心目標)
        'TRADITIONAL_AES_ASSET': '#27AE60', # 🟢 翡翠綠 (安全資產)
        'SECRET_LEAKAGE': '#C0392B',        # 🔴 深磚紅 (Critical)    
        'PQC_KEM_ML_KEM': '#2980B9',       # 🔵 深海藍 (PQC 核心目標)
        'PQC_SIGN_ML_DSA': '#2980B9',       # 🔵 深海藍 (PQC 核心目標)
        'HARDCODED_SECRET_KEY': '#C0392B',      # 🔴 深磚紅 (Critical)
        'HARDCODED_PASSWORD': '#C0392B',      # 🔴 深磚紅 (Critical)
        'HARDCODED_CLOUD_CREDENTIAL': '#C0392B',# 🔴 深磚紅 (Critical)
        'HARDCODED_API_TOKEN': '#C0392B',      # 🔴 深磚紅 (Critical)
        'HARDCODED_PQC_PRIVATE_KEY': '#C0392B',# 🔴 深磚紅 (Critical)
        'WEAK_RANDOM_SOURCE': '#C0392B',      # 🔴 深磚紅 (Critical)
        'WEAK_ECC_CURVE': '#D35400',       # 🟠 深焦橙 (高風險)
        'WEAK_KDF_ITERATION_COUNT': '#D35400',       # 🟠 深焦橙 (高風險)
        'INSUFFICIENT_SALT_LENGTH': '#D35400',       # 🟠 深焦橙 (高風險)
        'RISKY_GCM_NONCE_LENGTH': '#D35400',       # 🟠 深焦橙 (高風險)
	}
    
    #colors = [color_map.get(label, '#95A5A6') for label in risk_counts.index]
    
    # 2. 統計數量並轉換為 DataFrame
    stats = df['Type'].value_counts().reset_index()
    stats.columns = ['Type', 'Count']

    # 3. 對應顏色
    # map 函式會根據 Type 填入對應的 Hex 色碼
    stats['Color'] = stats['Type'].map(color_map).fillna('#95A5A6') # 預設灰色

    # 4. [關鍵步驟] 依照「顏色」進行排序
    # 這樣相同的顏色 (Hex Code) 就會排在一起
    # 第二排序鍵是 Count (降序)，讓同顏色的區塊中，數量多的排前面
    stats = stats.sort_values(by=['Color', 'Count'], ascending=[True, False])

    fig = go.Figure(data=[go.Pie(
        labels=stats['Type'],
        values=stats['Count'],
        hole=.4, # 甜甜圈图
        marker=dict(colors=stats['Color']),
        hovertemplate='%{label}<br>數量: %{value}<extra></extra>' ,
        sort=False # [關鍵] 禁用 Plotly 的自動排序，強制使用我們上面排好的順序
    )])
    
    fig.update_layout(
        title_text="PQC 遷移與弱點風險分佈 (總資產數: {})".format(len(findings)),
        title_x=0.5,
		font_color="#E0E0E0",             # 標題和圖例文字顏色 (淺色)
        plot_bgcolor='#1E1E1E',           # 圖表繪圖區背景 (深色)
        paper_bgcolor='#1E1E1E'           # 整個圖表紙張背景 (深色)
    )
    
    # 转换为 HTML 字符串
    return fig.to_html(full_html=False, include_plotlyjs='cdn')

def format_findings_table(findings):
    """将详细发现列表格式化为 HTML 表格"""
    if not findings:
        return ""
    
    html = '<table border="1" style="width:100%; border-collapse: collapse;">'
    html += '<tr style="background-color:#eee;"><th>#</th><th>位置</th><th>類型</th><th>代碼片段</th><th>修補建議</th></tr>'
    
    for i, f in enumerate(findings):
        color = 'red' if 'WEAK' in f['Type'] or 'SECRET' in f['Type'] else 'blue'
        
        # 避免代码片段破坏 HTML 结构
        code_safe = f['CodeSnippet'].replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>').replace('|', '/')
        
        html += f"""
        <tr>
            <td>{i+1}</td>
            <td>{f['Location']}</td>
            <td><strong style="color: {color};">{f['Type']}</strong></td>
            <td><code>{code_safe}</code></td>
            <td>{f['FixSuggestion']}</td>
        </tr>
        """
    html += '</table>'
    return html

def generate_full_report_html(findings):
    """生成包含圖表和表格的最終 HTML 報告"""
    
    chart_html = generate_risk_pie_chart(findings)
    table_html = format_findings_table(findings)
   

	# 設置深色模式的顏色代碼
    BG_COLOR = '#121212'   # 極深灰色/接近黑色
    TEXT_COLOR = '#e0e0e0' # 淺灰色 (適合深色模式的文字顏色)
    CONTAINER_BG = '#1e1e1e' # 內容框的深灰色


    final_html = f"""
    <!DOCTYPE html>
    <html lang="zh-TW">
    <head>
        <meta charset="UTF-8">
        <title>PQC 混合審計儀表板</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                background-color: {BG_COLOR}; 
                color: {TEXT_COLOR}; /* 全局文字顏色 */
            }}
            .container {{ 
                max-width: 1200px; 
                margin: auto; 
                background: {CONTAINER_BG}; /* 內容框背景 */
                padding: 20px; 
                box-shadow: 0 0 10px rgba(0,0,0,0.5); 
                border-radius: 8px;
            }}
            h1 {{ color: {TEXT_COLOR}; }} /* 標題顏色 */
            /* 修正表格背景，確保在深色背景下可讀 */
            table tr th {{ background-color: #333; color: #fff; }}
            table tr td {{ border-color: #444; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PQC 混合審計工具報告</h1>
            <p><strong>掃描時間:</strong> {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>總發現資產與弱點數:</strong> {len(findings)}</p>
            
            <h2>風險分佈儀表板</h2>
            <div id="plotly-chart">
                {chart_html}
            </div>
            
            <h2>詳細資產與漏洞清單</h2>
            {table_html}
        </div>
    </body>
    </html>
    """
    return final_html

# --- 主程序入口修改 (調用報告生成函數) ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 pqc_ast_scanner.py <檔案路徑> | <目錄路徑>")
        sys.exit(1)

    path_to_scan = sys.argv[1]
    
    if not os.path.exists(path_to_scan):
        print(f"❌ 錯誤: 找不到路徑 {path_to_scan}。")
        sys.exit(1)

    try:
        if os.path.isdir(path_to_scan):
            findings = scan_project_recursive(path_to_scan)
        else:
            findings = scan_file(path_to_scan)

    except Exception as e:
        print(f"致命錯誤：掃描過程中發生異常: {e}")
        sys.exit(1)
        
    
    # 1. 生成 CBOM JSON
    cbom_json_content = generate_cbom_json(findings)
    cbom_filename = "PQC_CBOM_Inventory.json"
    with open(cbom_filename, 'w', encoding='utf-8') as f:
        json.dump(cbom_json_content, f, indent=4)
        
    # 2. 生成 HTML 視覺化報告
    HTML_FILENAME = "PQC_Risk_Dashboard.html"
    full_html_content = generate_full_report_html(findings)
    
    try:
        with open(HTML_FILENAME, 'w', encoding='utf-8') as f:
            f.write(full_html_content)
        
        # 取得 HTML 檔案的絕對路徑 (確保瀏覽器能正確找到檔案)
        file_path = os.path.abspath(HTML_FILENAME)

        # 3. 輸出到終端機 (簡化輸出)
        print("\n" + "=" * 60)
        print("✅ 掃描完成！")
        print(f"總發現問題數: {len(findings)}")
        print(f"   -> 加密資產清單: {cbom_filename}")
        print(f"   -> 視覺化報告: {HTML_FILENAME} (請在瀏覽器中打開此文件查看儀表板)")
        print("=" * 60)
        
        # 3. [新增] 自動開啟瀏覽器
        print(f"🚀 正在開啟瀏覽器檢視報告...")
        webbrowser.open(f"file://{file_path}")

    except Exception as e:
        print(f"❌ 寫入報告失敗: {e}")
