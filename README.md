# ⚛️ PQC-AST-Scanner：後量子密碼遷移自動化盤點框架

## 🌟 專案簡介 (Introduction)

PQC-AST-Scanner 是一個跨語言（Python, Java）的靜態分析工具，旨在自動化盤點專案原始碼中潛在的**量子脆弱 (PQC Target)** 和**不安全**的密碼學資產。

本工具的核心價值在於利用 **抽象語法樹 (AST)** 進行精確的語義分析，取代傳統的字串比對，並以 **CBOM (密碼學物料清單)** 和 **Plotly 互動式報告**兩種格式輸出結果，為企業的後量子密碼學遷移 (PQC Migration) 提供堅實的數據基礎。

## 🚀 核心技術 (Core Technology)

| 技術 | 說明與優勢 |
| :--- | :--- |
| **AST 靜態分析** | 框架的核心。透過解析程式碼的語義結構，精準鎖定並分析 **函式呼叫** 和 **參數配置** (例如：RSA 密鑰長度是否小於 2048 bits，AES 是否使用不安全的 ECB 模式)，實現高精準度盤點。 |
| **跨語言支援** | 整合 **Python `ast`** 和 **`javalang`** 庫，在單一流程中同時處理多種語言的程式碼。 |
| **Plotly 視覺化報告** | **核心亮點：** 將掃描數據即時轉換為**高互動性的圓餅圖**，生成使用者友善的 **HTML 網頁報告**，用於直觀的風險分佈分析。 |
| **CBOM 輸出標準** | 生成符合簡化 CycloneDX 標準的 **CBOM JSON** 報告，確保輸出結果可被自動化安全工具鏈無縫集成。 |

## 🛠️ 環境設置與安裝 (Setup)

本專案強烈建議在**虛擬環境 (venv)** 中運行。

### 1. 系統要求

* **Python:** 3.9+

### 2. 設置步驟

1.  **克隆專案：**
    ```bash
    git clone [Your-Repo-Link]
    cd PQC-AST-Scanner
    ```

2.  **建立並啟動虛擬環境：**
    ```bash
    python -m venv pqc_env
    source pqc_env/bin/activate  # Linux / macOS
    # .\pqc_env\Scripts\activate  # Windows PowerShell
    ```

3.  **安裝依賴：**
    ```bash
    # 需要安裝數據處理、解析器和視覺化工具
    pip install javalang pycparser pandas plotly
    ```

## 📜 使用方法 (Usage)

本專案透過 CLI 介面運行，只需傳入要掃描的檔案或目錄路徑。

```bash
python pqc_ast_scanner.py <檔案路徑> | <目錄路徑>
