# pqc_ast_scanner.py - 自製 PQC 混合審計工具 (借鑒 Bandit/Semgrep 理念)

import ast
import sys
import os

# --- PQC 知識庫與修復建議 (借鑒 PQCA 的優點) ---
PQC_KNOWLEDGE_BASE = {
    # 规则 ID: [风险类型, 风险等级, 修复建议]
    "B303": ["WEAK_HASH_SHA1", "HIGH", "替换为 hashlib.sha256/sha3，SHA1 易受碰撞攻击。"],
    "B304": ["WEAK_CIPHER_DES", "HIGH", "停用 DES/3DES，改用 AES-256 GCM 模式。"],
    "B324": ["WEAK_HASH_MD5", "CRITICAL", "立即移除 MD5，替换为 SHA256。"],
    "B413_RSA": ["PQC_TARGET_RSA", "INFO", "量子脆弱：考虑替换为 CRYSTALS-Kyber (KEM)。"],
    "B413_AES": ["TRADITIONAL_AES", "LOW", "传统对等加密，确保使用 GCM/CCM 模式。"]
}


# --- 核心分析引擎：AST 访问器 (借鑒 Bandit 的优點) ---
class PQC_AST_Visitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def visit_Call(self, node):
        """访问 AST 中的所有函数调用节点"""
        
        full_name = self._get_full_name(node.func)
        
        # --- PQC 规则匹配 (借鑒 Semgrep 的模式匹配理念) ---
        
        # 1. 量子脆弱的 RSA 资产盘点
        if "RSA.generate" in full_name:
            self.report_finding(node, "B413_RSA")

        # 2. 弱哈希函数检测
        elif "hashlib.sha1" in full_name:
            self.report_finding(node, "B303")
            
        elif "hashlib.md5" in full_name:
            self.report_finding(node, "B324")
            
        # 3. 弱加密算法检测
        elif "Crypto.Cipher.DES" in full_name:
            self.report_finding(node, "B304")
            
        elif "AES.new" in full_name:
            # 检查是否是 AES.new 的调用，进一步判断是否使用了 ECB 模式 (进阶逻辑)
            if self._is_ecb_mode(node):
                self.report_finding(node, "B413_AES", "警告：使用了不安全的 AES/ECB 模式。")
            else:
                 self.report_finding(node, "B413_AES") # 标记 AES 使用
            
        # 确保继续遍历子节点
        self.generic_visit(node)

    # --- 辅助函数：获取完整函数名 ---
    def _get_full_name(self, node):
        """递归解析属性访问，生成 'module.class.function' 字符串"""
        if isinstance(node, ast.Attribute):
            return self._get_full_name(node.value) + "." + node.attr
        elif isinstance(node, ast.Name):
            return node.id
        return ""
    
    # --- 进阶辅助函数：检查 ECB 模式 (模仿 Bandit 的数据流分析) ---
    def _is_ecb_mode(self, call_node):
        """检查 AES.new 调用中是否传入了 AES.MODE_ECB 模式"""
        for keyword in call_node.keywords:
            if keyword.arg == 'mode':
                # 这是一个简单的检查：如果 mode 参数的名称包含 ECB，则返回 True
                return 'ECB' in ast.unparse(keyword.value)
        return False # 如果没有指定 mode，则默认检查失败

    # --- 报告生成 ---
    def report_finding(self, node, rule_id, custom_message=None):
        info = PQC_KNOWLEDGE_BASE.get(rule_id, {"type": "UNKNOWN", "fix": "N/A"})
        
        self.findings.append({
            "RuleID": rule_id,
            "Type": info['type'],
            "Location": f"{self.filename}:{node.lineno}",
            "CodeSnippet": ast.unparse(node).strip(),
            "Message": custom_message if custom_message else info.get('message', 'N/A'),
            "FixSuggestion": info['fix'] # 最终的修补建议
        })

# --- 运行主程序 ---
def scan_project(filepath):
    with open(filepath, 'r') as f:
        code = f.read()
    
    # 解析代码为 AST
    tree = ast.parse(code)
    
    # 运行访问器
    visitor = PQC_AST_Visitor(filepath)
    visitor.visit(tree)
    
    return visitor.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 pqc_ast_scanner.py <Python 檔案路徑>")
        sys.exit(1)

    findings = scan_project(sys.argv[1])
    
    print("\n--- 專案 PQC 靜態掃描報告 (自製工具) ---")
    if not findings:
        print("✅ 未發現任何 PQC 相關的傳統加密資產或弱點。")
    else:
        pqc_targets = [f for f in findings if 'PQC_TARGET' in f['RuleID']]
        weak_ciphers = len(findings) - len(pqc_targets)
        
        print(f"總發現問題數: {len(findings)}")
        print(f"待遷移資產數: {len(pqc_targets)}\n")

        for i, f in enumerate(findings):
            print(f"----- FINDING #{i+1} -----")
            print(f"類型: {f['Type']}")
            print(f"位置: {f['Location']}")
            print(f"代碼: {f['CodeSnippet']}")
            print(f"問題: {f['Message']}")
            print(f"🟢 修補建議: {f['FixSuggestion']}")
