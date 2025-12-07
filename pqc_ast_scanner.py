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
	
    def visit_Assign(self, node):
        """偵測硬編碼密鑰 (借鑒 Bandit B105)"""
        
        # 僅檢查單目標賦值 (例如 WEAK_KEY = "...")
        if len(node.targets) == 1:
            target = ast.unparse(node.targets[0]).upper()
            line_num = node.lineno
            
            # 檢查變數名是否包含 'KEY', 'PASS', 'SECRET'
            if ("KEY" in target or "PASS" in target or "SECRET" in target):
                
                # 檢查右側賦值是否為字符串常量
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    value = node.value.value
                    
                    # 檢查字符串長度 (避免誤判單個字母)
                    if len(value) > 10 and not value.isnumeric(): 
                        finding = report_finding(node, self.filename, line_num, "B105_HARDCODED_SECRET")
                        self.findings_list.append(finding)
                            
        self.generic_visit(node) # 確保繼續遍歷子節點

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
    risk_counts = df['Type'].value_counts()
    
    # 定義顏色：確保高風險 (WEAK, SECRET) 使用紅色/橙色
    color_map = {
        'WEAK_HASH_SHA1': '#D35400',       # 🟠 深焦橙 (高風險)
        'WEAK_HASH_MD5': '#C0392B',        # 🔴 深磚紅 (Critical)
        'WEAK_CIPHER_DES': '#C0392B',      # 🔴 深磚紅 (Critical)
        'WEAK_ASSET_RSA': '#D35400',       # 🟠 深焦橙 (高風險)
        'WEAK_CIPHER_MODE': '#C0392B',     # 🔴 深磚紅 (Critical)
        'WEAK_IV_NONCE': '#D35400',        # 🟠 深焦橙 (高風險)
        'PQC_TARGET_RSA': '#2980B9',       # 🔵 深海藍 (PQC 核心目標)
        'PQC_TARGET_ECC': '#2980B9',       # 🔵 深海藍
        'TRADITIONAL_AES_ASSET': '#27AE60', # 🟢 翡翠綠 (安全資產)
        'SECRET_LEAKAGE': '#C0392B'        # 🔴 深磚紅 (Critical)    
	}
    
    colors = [color_map.get(label, '#95A5A6') for label in risk_counts.index]
    
    fig = go.Figure(data=[go.Pie(
        labels=risk_counts.index, 
        values=risk_counts.values,
        hole=.4, # 甜甜圈图
        marker=dict(colors=colors),
        hovertemplate='%{label}<br>數量: %{value}<extra></extra>' 
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
        
        # 3. 輸出到終端機 (簡化輸出)
        print("\n" + "=" * 60)
        print("✅ 掃描完成！")
        print(f"總發現問題數: {len(findings)}")
        print(f"   -> 加密資產清單: {cbom_filename}")
        print(f"   -> 視覺化報告: {HTML_FILENAME} (請在瀏覽器中打開此文件查看儀表板)")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ 寫入報告失敗: {e}")


