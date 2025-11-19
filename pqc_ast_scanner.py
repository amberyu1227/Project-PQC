import ast
import sys
import os
import javalang          # 需要安裝: pip install javalang
import pycparser         # 需要安裝: pip install pycparser
from pycparser import c_parser, c_ast, parse_file

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
}
# ----------------------------------------


# --- 核心邏輯：報告生成 (作為獨立函數) ---
def report_finding(node, filename, line, rule_id, custom_message=None):
    info = PQC_KNOWLEDGE_BASE.get(rule_id, {"type": "UNKNOWN", "message": "未知規則", "fix": "N/A"})
    
    # 根據節點類型獲取代碼片段（適應 Python, Java, C）
    if isinstance(node, (ast.Call, ast.Attribute)):
        code_snippet = ast.unparse(node).strip()
    elif hasattr(node, 'value'):
        # 適用於 javalang 的 Literal 節點
        code_snippet = str(node.value).strip('"') 
    elif hasattr(node, 'name'):
        # 適用於 C AST (FuncCall)
        code_snippet = str(node.name) if isinstance(node, c_ast.FuncCall) else str(node)
    else:
        code_snippet = str(node)

    return {
        "RuleID": rule_id,
        "Type": info.get('type', 'UNKNOWN_TYPE'),
        "Location": f"{filename}:{line}",
        "CodeSnippet": code_snippet,
        "Message": custom_message if custom_message else info.get('message', 'N/A'),
        "FixSuggestion": info.get('fix', 'N/A')
    }

# --- Python 掃描核心 ---
class PQC_AST_Visitor(ast.NodeVisitor):
    def __init__(self, filename, findings_list):
        self.filename = filename
        self.findings_list = findings_list 

    def visit_Call(self, node):
        full_name = self._get_full_name(node.func)
        
        # 1. 弱雜湊 (最高優先級別)
        if "hashlib.sha1" in full_name:
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B303"))
        elif "hashlib.md5" in full_name: 
            self.findings_list.append(report_finding(node, self.filename, node.lineno, "B324"))
            
        # 2. 量子脆弱/弱加密 (DES, RSA)
        elif "Crypto.Cipher.DES" in full_name:
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

def scan_python(filepath):
    findings_list = []
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath) 
    visitor = PQC_AST_Visitor(filepath, findings_list)
    visitor.visit(tree)
    return findings_list


# --- Java 掃描核心 ---
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
        # 只尋找方法呼叫 (MethodInvocation)
        if isinstance(node, javalang.tree.MethodInvocation) and node.member == 'getInstance':
            
            # 檢查參數是否為字符串字面量
            if node.arguments and isinstance(node.arguments[0], javalang.tree.Literal):
                arg_value = node.arguments[0].value.strip('"').upper()
                line_num = node.position.line
                
                # 1. 弱雜湊 (優先級最高)
                if "SHA1" in arg_value:
                    findings_list.append(report_finding(node, filepath, line_num, "B303"))
                elif "MD5" in arg_value:
                    findings_list.append(report_finding(node, filepath, line_num, "B324"))

                # 2. 弱加密 (DES)
                elif "DES" in arg_value:
                    findings_list.append(report_finding(node, filepath, line_num, "B304")) 
                
                # 3. AES 模式檢查 (必須在 DES 之後，避免與 ECB/GCM 衝突)
                elif "AES" in arg_value:
                    if "ECB" in arg_value:
                        # 3.1 偵測 AES/ECB 模式 (不安全)
                        findings_list.append(report_finding(node, filepath, line_num, "B413_AES_WEAK")) 
                    else:
                        # 3.2 偵測其他 AES 模式 (資產盤點)
                        # 將所有非 ECB 的 AES 視為安全資產盤點
                        findings_list.append(report_finding(node, filepath, line_num, "B413_AES_SAFE"))

                # 4. PQC 遷移目標 (RSA & ECC - 放到最後檢查，避免與 AES/DES 衝突)
                elif "RSA" in arg_value:
                    # 這裡沒有實現 Java 的 Key Size 檢查，只標記為 PQC 目標
                    findings_list.append(report_finding(node, filepath, line_num, "B413_RSA"))
                elif "EC" in arg_value or "ECDSA" in arg_value or "ECDH" in arg_value:
                    # 標記 ECC 
                    findings_list.append(report_finding(node, filepath, line_num, "B413_ECC"))
                    
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 pqc_ast_scanner.py <檔案路徑> | <目錄路徑>")
        sys.exit(1)

    path_to_scan = sys.argv[1]
    
    if not os.path.exists(path_to_scan):
        print(f"❌ 錯誤: 找不到路徑 {path_to_scan}。請確認路徑是否正確。")
        sys.exit(1)

    try:
        if os.path.isdir(path_to_scan):
            findings = scan_project_recursive(path_to_scan)
        else:
            findings = scan_file(path_to_scan)

    except Exception as e:
        print(f"致命錯誤：掃描過程中發生異常: {e}")
        sys.exit(1)
        
    print("\n--- 專案 PQC 靜態掃描報告 (自製工具) ---")
    print(f"總發現問題數: {len(findings)}\n")

    # (打印詳細報告邏輯)
    for i, f in enumerate(findings):
        print(f"----- FINDING #{i+1} -----")
        print(f"類型: {f['Type']} ({f['RuleID']})")
        print(f"位置: {f['Location']}")
        print(f"代碼: {f['CodeSnippet']}")
        print(f"問題: {f['Message']}")
        print(f"🟢 修補建議: {f['FixSuggestion']}")