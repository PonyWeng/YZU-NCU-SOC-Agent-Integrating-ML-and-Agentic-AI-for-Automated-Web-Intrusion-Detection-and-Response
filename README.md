# NCU-PDCLAB mini SIEM — 自建安全監控與應變平台

以多服務日誌、機器學習、OWASP CRS WAF 與 LINE 資安助理為核心的本機 SIEM。
目前已移除 Elasticsearch、Logstash、Kibana 的程式與啟動依賴，改由 SQLite 與 FastAPI 提供儲存、查詢、告警與自建儀表板。

## 功能

- 安全總覽：請求／攻擊趨勢、偵測分類、来源數、待處理事件、收集器狀態。
- 日誌中心：時間、來源 IP、分類、HTTP 狀態與關鍵字搜尋，分頁、原始日誌、CSV 匯出。
- 事件工作佇列：規則證據、調查註記、新事件／調查中／已處理／誤報狀態。
- 關聯拓樸：依真實日誌連結來源 IP 與目標服務，顯示最多 12 組關聯，點擊來源查詢。
- 封鎖管理：共用黑名單、Apache .htaccess 寫入與手動解除封鎖。
- 規則設定：同一來源及同一攻擊類型的時間窗計數、門檻、冷卻與嚴重度。
- 操作紀錄：記錄規則、事件、封鎖管理與歷史匯入操作。
- LINE Agent：保留共用介面，等待外部 AI Provider Gateway（Gemini／OpenAI）。

目前規則是可調整的起點，預設停用，不是已校準的生產偵測規則。沒有啟用自動封鎖。

## 架構

```text
Apache／Flask／Django → OWASP CRS WAF → 統一日誌與 CRS audit log
                                      ↓
                              siem.collector → SQLite
                                    ├─ FastAPI → 自建儀表板（127.0.0.1:8000）
                                    ├─ 可設定規則 → 事件／證據 → LINE 通知佇列
                                    └─ LINE Agent → 查詢、威脅情報與封鎖

LINE → ngrok（選用）→ LINE 專用 webhook（127.0.0.1:8002）
外部 AI Provider（選用）→ LINE Agent 與 Web AI
```

原始事件時間與接收時間分開保存。事件與檔案讀取位置在同一交易提交，失敗可重試。
收集器辨識檔案輪替與截短，保留尚未完成的最後一行；不再使用 prediction_output.json 作為程序間訊息傳遞。

## 啟動

### Docker Compose（建議用於搬移與比賽 Demo）

新設備只需安裝 Docker Desktop，將專案與私下保存的 `secrets.env` 放在同一目錄後執行：

```bash
docker compose up -d --build
docker compose ps
```

開啟 `http://localhost:8000`。三個 WAF 入口分別為 `80`、`8081`、`8082`；LINE webhook 使用 `8002`。第一次啟動會建立全新的 SQLite、帳號、事件、IOC 與日誌資料。停止服務使用 `docker compose down`；若要連同新設備產生的所有資料一起清空，使用 `docker compose down -v`。

敏感設定不放入映像或 Git。原設備可執行：

```bash
python tools/export_secrets.py
```

這會將 `.env` 內的 LINE、ngrok、情資金鑰，以及資料庫內目前使用的 AI Provider／模型／API Key，整理成單一 `secrets.env`。只需透過安全方式把此檔搬到新設備的專案根目錄。若 LINE 或 ngrok 欄位完整，匯出工具會自動開啟對應容器功能。

Compose 使用具名 volume 保存新設備產生的日誌與 SQLite；這些資料不會包進原始碼或 Docker image。`htdocs` 保留 bind mount，讓 SIEM 寫入的 Apache 封鎖規則能立即套用到測試靶機。

在 Ubuntu 主機執行攻擊示範時，基本腳本預設會對 SQL Injection、XSS、Directory Traversal 各送 5 筆：

```bash
python attack_scripts.py --target http://127.0.0.1 --count 5
```

完整規則覆蓋測試還會觸發流量暴增、多服務探測、404、5xx 與情資命中等行為規則。密碼建議透過環境變數提供，避免留在 shell history：

```bash
export SIEM_TEST_PASSWORD='你的管理員密碼'
python rule_coverage_attack.py --host 127.0.0.1 --attack-count 5
```

若從另一台電腦對 Ubuntu 伺服器執行，將 `--host` 改為該伺服器 IP。

使用既有的 Python 3.10 PonyNIDS 環境：

一按鍵啟動完整服務（Git Bash / WSL）：

```bash
./start.sh
```

這會依序啟動三個受保護服務及 OWASP CRS WAF，再啟動儀表板、ML／WAF 日誌收集器、LINE webhook、LINE 通知重試與 ngrok。LINE webhook 使用獨立的 `127.0.0.1:8002`，不會把儀表板管理 API 暴露到 ngrok。

Windows 可使用：

```powershell
python start.py --demo
# 包含 LINE 與 ngrok：
python start.py --demo --line --ngrok
python stop.py
python stop.py --docker
```

WAF 對外入口為 Apache `:80`、Flask `:8081`、Django `:8082`。比賽版預設採 CRS PL1／Detection Only，只記錄規則命中而不阻擋。`stop.py --docker` 會一併停止 WAF 與靶機容器。

如果只想看儀表板而不啟動其他服務：

```powershell
conda activate PonyNIDS
pip install -r requirements.txt
python start.py --dashboard-only
```

開啟 http://127.0.0.1:8000 。儀表板本身不需要 Docker 或 AI Provider。
如 8000 已占用，可加上 `--port 8080`；啟動程式不會終止占用連接埠的其他程序。

匯入舊版本預測資料：

```powershell
python start.py --dashboard-only --import-legacy prediction_output.json
```

匯入按原始 ID 去重，保留日誌中的事件時間，不觸發告警／封鎖。舊資料可能不在最近 24 小時內，請在儀表板選擇「全部資料」。

開始收集完整 Demo 流量：

```powershell
python start.py --demo
```

收集器首次啟動從檔案尾端追蹤新流量，之後從已保存位置恢復。首次啟動前的紀錄可透過歷史匯入或下列指令匯入；不要對同一份歷史資料同時使用兩種匯入方式，以免來源 ID 不同造成重複。

```powershell
python predict.py -l apache-logs/access.log -m MODELS/model_RandomForestClassifier.pkl
```

日誌／模型路徑由 `.env` 中 `ACCESS_LOG`、`MODEL_PATH` 指定；預設採專案中的 Apache 日誌及 RandomForest 模型。程序輸出保存在 `runtime/`。

## 選用 LINE 與外部 AI

設定 `.env` 中 LINE access token、channel secret、`LINE_USER_IDS`（允許管理平台的 LINE 使用者及通知接收人），然後：

```powershell
python start.py --line
# 如需 ngrok：
python start.py --line --ngrok
```

將印出的 `/webhook` URL 設定到 LINE Developers。ngrok 只連接 8002 的 LINE 專用 app，該 app 沒有儀表板或管理 API。

```powershell
```

AI Provider 尚未設定時，LINE 與 Web Agent 會清楚提示設定 Gemini／OpenAI；不會啟動或載入本地模型。

## 規則行為

初始三項規則分別對應 SQLi、XSS、Directory Traversal，預設全部停用。
啟用後，對新入庫且事件時間在最近 5 分鐘內的紀錄進行判定；歷史匯入不判定。
每項規則按 `來源 IP + 攻擊類型` 計數，使用事件時間的滑動時間窗。
同一規則／來源在冷卻期間不建立新的事件。已建立事件保存當時證據快照，不會隨後續流量變更。
LINE 通知按接收人保存寄送狀態，失敗以退避方式重試；網路逾時可能造成外部服務已收件但本機未確認，因此不保證 exactly-once。

## 本機存取與資料管理

- 第一版只提供本機管理，尚無多人登入／角色權限；請勿將管理 app 對外代理。
- 管理 API 檢查本機來源、Host 與跨站操作。LINE webhook 額外驗證簽章與使用者白名單。
- CSV 匯出避免將 payload 當成試算表公式；UI 以文字呈現日誌，不執行 payload。
- 封鎖修改使用檔案鎖與原子替換；Apache 實際效果仍取決於服務啟動、AllowOverride 與來源 IP 設定。
- SQLite 採 WAL 與索引；目前未提供自動保留期限清理及大量分散式收集。
- 拓樸是日誌來源與受保護服務的關聯，並非實體網路設備自動探索。
- `.env` 與 `runtime/` 不提交；執行中的 SQLite 請使用 SQLite backup API 備份，或停止程序後複製資料檔。

## 從 ELK 遷移

Compose 包含 Apache、Flask、Django 與三個 OWASP CRS WAF 入口。舊 ELK／RAG 容器若仍執行，需確認名稱後停止／移除；本次不刪除舊資料卷。
現有 `prediction_output.json` 可匯入，僅存在 Elasticsearch 的歷史資料仍需另外匯出成可對應的事件紀錄。
舊 `ES_*` 環境變數已不使用，可在遷移完成後自行清理。`temp_files/` 是原有歷史／實驗資料，不屬於執行路徑。

## 驗證

```powershell
python -m unittest discover -s tests -v
node --check dashboard/app.js
```

測試使用獨立暫存資料庫及封鎖檔案，不修改實際黑名單、不傳送 LINE、不呼叫模型。

## 主要檔案

| 路徑 | 功能 |
|---|---|
| `start.py` | 啟動儀表板、收集器及選用 LINE 服務 |
| `api.py` | 本機管理 app 與獨立 LINE webhook app |
| `siem/store.py` | SQLite schema、事件查詢、規則及稽核 |
| `siem/collector.py` | 日誌解析、ML 推論、checkpoint、歷史匯入 |
| `siem/routes.py` | 管理 API 與 CSV 匯出 |
| `siem/notifications.py` | LINE 通知重試 |
| `dashboard/` | 無外部 CDN 依賴的繁體中文儀表板 |
| `assistant/` | LINE Agent、威脅情報與共用 Apache 封鎖 |
| `tests/test_siem.py` | 離線整合測試 |
