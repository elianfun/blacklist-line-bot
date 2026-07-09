# 黑名單管理 LINE Bot

透過 LINE 傳送 IP，自動驗證、去重、過濾白名單後，即時更新防火牆黑名單伺服器（HFS）上正在服務的 `ip.txt`。用於**少量、臨時性**的 IP 封鎖需求；大量批次匯入仍使用 [`D:\claude\blacklist`](../blacklist) 底下的 `ipip.py` + CSV 流程，兩者互不影響、各自獨立運作。

---

## 目錄

- [功能總覽](#功能總覽)
- [系統架構](#系統架構)
- [申請 LINE Official Account + Messaging API](#申請-line-official-account--messaging-api)
- [伺服器端部署](#伺服器端部署)
- [設定 .env](#設定-env)
- [設定授權名單](#設定授權名單)
- [使用 ngrok 對外開放](#使用-ngrok-對外開放)
- [設定 LINE Webhook](#設定-line-webhook)
- [與本機批次匯入工具的關係](#與本機批次匯入工具的關係)
- [常見問題](#常見問題)
- [實作知識點](#實作知識點)

---

## 功能總覽

| 功能 | 說明 |
|------|------|
| 接收 IP 訊息 | 支援單筆或多筆（一行一個、空白或逗號分隔皆可） |
| 白名單保護 | 內建網段白名單，命中則自動略過，不會被誤加入黑名單 |
| 去重 | 自動比對現有 `ip.txt`，已存在的 IP 不重複加入 |
| 移除 IP | 訊息開頭打「刪除」（或 `移除`/`remove`/`delete`/`del`）＋ IP，會先確認該 IP 存在才移除，查無此 IP 不會誤動作 |
| 非文字訊息防呆 | 傳圖片、貼圖等非文字內容會回覆提示，不會被忽略 |
| 混雜文字防呆 | 訊息若夾雜非 IP 的文字（例如中文句子裡帶了看起來像 IP 的數字），整則不處理，避免誤判 |
| 授權控管 | 只有白名單內的 LINE userId 能觸發變更，其餘訊息會被拒絕 |
| 即時生效 | 通過驗證後幾秒內覆蓋伺服器上正在服務的 `ip.txt` |
| 風格化回覆 | 回覆格式比照 `ipip.py` 主控台輸出，維持操作體感一致 |

---

## 使用方式

**新增 IP**（預設行為，直接傳 IP 即可）：

```
1.2.3.4
5.6.7.8
```

**移除 IP**（開頭加上「刪除」，同行或換行接 IP 皆可）：

```
刪除
1.2.3.4
5.6.7.8
```

或

```
刪除 1.2.3.4
```

移除前會先確認該 IP 是否存在於目前的 `ip.txt`，存在才移除；查無此 IP 會在回覆中列出「查無此 IP」，不會誤動作。

---

## 系統架構

```
LINE App
  │  傳送 IP 訊息
  ▼
LINE Messaging API
  │  POST /webhook (HTTPS)
  ▼
ngrok tunnel  ──────────────────────────────┐
  │  轉發到 127.0.0.1:8000                    │ 對外網址會在 ngrok
  ▼                                          │ 重啟後改變（免費版限制）
Flask app (main.py, systemd: blacklist-bot)  │
  │  1. 驗證 X-Line-Signature（Channel secret）
  │  2. 檢查 userId 是否在 authorized_users.txt
  │  3. 解析 IP、比對白名單 / 現有 ip.txt 去重
  │  4. 寫入 staging/ip.txt
  │  5. sudo -n blacklist-apply-update.sh
  ▼
/usr/local/sbin/blacklist-apply-update.sh（root 擁有，僅此腳本可免密碼 sudo）
  │  覆蓋 staging/ip.txt → 正式檔案，並修正 root:root 644 權限
  ▼
/home/inno/hfs/share/blacklist/ip.txt  ← HFS (以 root 執行) 對外服務這個檔案
```

**權限設計重點**：Flask app 以一般使用者 `inno` 執行，本身完全沒有 sudo 權限，只透過 `/etc/sudoers.d/blacklist-bot` 精準授權「**免密碼執行這一支腳本、不能做其他任何 sudo 動作**」，腳本本身也是 root 擁有、`inno` 無法竄改。即使 bot 邏輯有漏洞，攻擊面也被鎖死在「覆蓋這一個檔案」，無法進一步取得 root。

---

## 申請 LINE Official Account + Messaging API

1. 前往 [LINE Developers Console](https://developers.line.biz/)，用 LINE 帳號登入，選擇或建立一個 **Provider**
2. 現在 LINE 已不能直接在 Developers Console 建立 Messaging API channel，要先點 **Create a LINE Official Account**，跳轉到 [LINE Official Account Manager](https://manager.line.biz/) 建立官方帳號
3. 建立完成後，進入該帳號後台「**設定 → Messaging API**」，點「**啟用 Messaging API**」，掛載到前面選好的 Provider
4. 回到 LINE Developers Console，該帳號會出現在 Provider 底下的 Channels 列表
5. 進入 Channel：
   - **Basic settings** 頁籤：複製 **Channel ID**、**Channel secret**
   - **Messaging API** 頁籤：**Channel access token (long-lived)** 按 Issue 核發，複製 **Access Token**
6. 回到官方帳號後台「**設定 → 回應設定**」：
   - **回應模式**務必切成「**機器人**」（Bot），否則訊息會被官方帳號自己的聊天/自動回覆攔截，不會轉發到 webhook
   - 關閉「自動回應訊息」「加入好友歡迎訊息」，避免干擾 bot 邏輯

---

## 伺服器端部署

目標伺服器：`192.168.50.50`（同時也是 HFS 黑名單發布伺服器）

```
/home/inno/blacklist-bot/
├── app/
│   ├── main.py              # Flask webhook 主程式
│   ├── whitelist.py         # 白名單規則（需與本機 ipip.py 手動同步）
│   ├── requirements.txt
│   ├── .env                 # 真實憑證，不進版控
│   └── authorized_users.txt # 真實授權名單，不進版控
├── staging/
│   └── ip.txt                # bot 寫入的暫存檔，apply script 從這裡覆蓋到正式路徑
└── venv/                     # Python 3.12 虛擬環境
```

### 建置步驟

```bash
# 系統套件（Ubuntu 24.04 預設缺這些）
sudo apt install python3.12-venv python3-pip git -y

# 專案資料夾與虛擬環境
mkdir -p /home/inno/blacklist-bot/{app,staging}
cd /home/inno/blacklist-bot
python3 -m venv venv
./venv/bin/pip install -r app/requirements.txt
```

### 安裝權限腳本（一次性，需 root）

```bash
sudo install -o root -g root -m 755 deploy/blacklist-apply-update.sh /usr/local/sbin/blacklist-apply-update.sh
sudo install -o root -g root -m 440 deploy/blacklist-bot-sudoers /etc/sudoers.d/blacklist-bot
sudo visudo -cf /etc/sudoers.d/blacklist-bot   # 驗證語法
```

### 安裝 systemd service

```bash
sudo install -o root -g root -m 644 deploy/blacklist-bot.service /etc/systemd/system/blacklist-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now blacklist-bot.service
sudo systemctl status blacklist-bot.service
```

Bot 綁定在 `127.0.0.1:8000`（僅本機迴環介面），跟 HFS 佔用的 `0.0.0.0:8888` 完全獨立、不衝突。

---

## 設定 .env

複製 `.env.example` 為 `app/.env`：

```env
LINE_CHANNEL_ID=你的_Channel_ID
LINE_CHANNEL_SECRET=你的_Channel_Secret
LINE_CHANNEL_ACCESS_TOKEN=你的_Channel_Access_Token
```

```bash
chmod 600 app/.env   # 只有執行 bot 的帳號能讀寫
```

---

## 設定授權名單

複製 `authorized_users.txt.example` 為 `app/authorized_users.txt`（每行一個 LINE userId）。

取得 userId 的方式：管理員直接傳訊息給 bot，未在名單內時 bot 會回覆：

```
您尚未被授權使用此功能。
您的 userId：
U452daa2f31758ee28b4ff96dc884ea89
請將此 ID 交給管理員加入授權名單。
```

把這串 ID 貼進 `authorized_users.txt` 存檔即可，**bot 每次收到訊息都會即時重新讀取這份清單，不需要重啟服務**。

---

## 使用 ngrok 對外開放

LINE Webhook 需要 HTTPS 公開網址，這裡用 ngrok 建立穿隧（不需在防火牆開對外 port）。

```bash
# 安裝（Ubuntu 官方 apt repo）
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok -y

# 設定 authtoken（去 https://dashboard.ngrok.com/get-started/your-authtoken 取得）
ngrok config add-authtoken 你的token
```

常駐執行：

```bash
sudo install -o root -g root -m 644 deploy/ngrok-blacklist-bot.service /etc/systemd/system/ngrok-blacklist-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now ngrok-blacklist-bot.service
```

查看目前對外網址：

```bash
curl -s http://127.0.0.1:4040/api/requests/http   # 或直接看 journalctl -u ngrok-blacklist-bot.service
```

> ⚠️ **免費版 ngrok 網址每次重啟都會變動**，重啟後要回 LINE Developers 重新設定 Webhook URL。若要固定網址，需升級 ngrok 付費方案並綁定 reserved domain。
>
> ⚠️ **ngrok 免費帳號整個帳號同時只能有 1 個 tunnel**，若你其他專案已經用同一組帳號開了 tunnel，這裡會啟動失敗（`ERR_NGROK_334`），需另外註冊新帳號或升級付費方案。

---

## 設定 LINE Webhook

1. 前往 LINE Developers Console（或 Official Account Manager）該 channel 的 **Messaging API** 頁籤
2. **Webhook URL** 填入 `https://你的ngrok網址/webhook`，儲存
3. 確認「回應設定」的回應模式為「機器人」（見上方申請章節）
4. 直接用手機傳訊息給官方帳號測試，比 Developers Console 的 Verify 按鈕更能反映真實情況

---

## 與本機批次匯入工具的關係

`D:\claude\blacklist\ipip.py` 是本機端的大量匯入工具，跟這個 LINE bot **完全脫鉤、沒有共用檔案或程式碼**：

- **少量、臨時新增**：走 LINE bot，直接改伺服器上正在服務的 `ip.txt`
- **大量批次匯入**：維持原本流程（改 `blacklist.csv` → 跑 `ipip.py` → 手動網頁上傳覆蓋）

⚠️ 兩者寫的是**同一個目的地檔案**。若 bot 已經加了幾筆 IP，之後才用本機舊流程做大量匯入，本機的 `ip.txt` 基準是舊的，覆蓋上去會蓋掉 bot 新增的部分。**大量匯入前，建議先把伺服器現在的 `ip.txt` 抓回本機同步**：

```powershell
scp inno@192.168.50.50:/home/inno/hfs/share/blacklist/ip.txt D:\claude\blacklist\ip.txt
```

白名單規則（`WHITELIST`）目前分別存在兩處，異動時**需手動同步**：
- 本機：`D:\claude\blacklist\ipip.py`
- 伺服器：`/home/inno/blacklist-bot/app/whitelist.py`

---

## 常見問題

**Q: 傳訊息給 bot 沒反應？**
先確認官方帳號後台「回應設定」的回應模式是「機器人」而不是「聊天」，否則訊息會被 LINE 自己攔截，不會送到 webhook。

**Q: Bot 回覆「處理失敗」？**
多半是 `sudo -n` 呼叫 `blacklist-apply-update.sh` 失敗，檢查 `sudo -n /usr/local/sbin/blacklist-apply-update.sh` 能否免密碼執行，以及 `/etc/sudoers.d/blacklist-bot` 是否還在。

**Q: ngrok 網址一直在變，很麻煩？**
免費版本來就會這樣，升級付費方案綁定固定 domain 可以解決，同時也能突破「整帳號僅 1 個 tunnel」的限制。

**Q: 想加的 IP 沒有被加入，也沒有錯誤訊息？**
檢查是否命中白名單（`whitelist.py` 的 `WHITELIST`），bot 回覆內容會明確列出「略過 N 個白名單 IP」。

**Q: 重開機後 bot / ngrok 沒有自動啟動？**
兩者都已設定 `systemctl enable`，理論上開機會自動啟動。可用 `systemctl status blacklist-bot ngrok-blacklist-bot` 確認狀態。

---

## 實作知識點

### 1. LINE Webhook 簽章驗證

LINE 在每個 webhook 請求都會帶 `X-Line-Signature` header，內容是用 **Channel secret** 對 request body 做 HMAC-SHA256 後 base64 編碼的結果。伺服器端用同樣方式重算一次並比對，可以確認請求真的來自 LINE、且內容沒有被竄改，避免任何人猜到網址就能偽造指令。

### 2. 最小權限的 sudo 設計

Bot process 完全不用 root 執行，也沒有廣泛的 sudo 權限。`/etc/sudoers.d/blacklist-bot` 只放行「對單一腳本、免密碼」這一條規則，腳本本身是 root 擁有、一般使用者無法修改。這樣即使 bot 程式碼有漏洞被利用，能造成的最大傷害也只是「覆蓋 ip.txt」，無法變成任意 root 指令執行。

### 3. Staging 檔案 + 覆蓋腳本，而不是讓 bot 直接寫正式檔案

正式檔案 `/home/inno/hfs/share/blacklist/ip.txt` 是 root 擁有、644 權限（因為 HFS 是用 `sudo` 以 root 身分執行，網頁上傳才能覆蓋）。Bot 帳號沒有直接寫入權限，所以設計成「bot 寫到自己有權限的 staging 資料夾 → 呼叫 root 腳本把 staging 內容複製過去並修正權限」，職責分離、權限邊界清楚。

### 4. 白名單邏輯與本機工具共用同一套演算法

`whitelist.py` 的 `build_whitelist` / `is_whitelisted` / `get_ip_obj` 三個函式，邏輯上完全對應本機 `ipip.py` 的同名函式（用 Python `ipaddress` 模組判斷 IP 是否落在某個 CIDR 網段內），確保「同一個 IP 在本機批次匯入和 LINE bot 兩條路徑，白名單判定結果一致」，避免出現一邊擋得住、一邊擋不住的不一致情況。

### 5. 授權名單即時生效，不需重啟

`load_authorized_users()` 在每次 webhook 請求時都重新讀取 `authorized_users.txt`，而不是啟動時載入一次快取。好處是管理員新增/移除授權對象後立即生效，不用重啟 bot service；代價是每次請求多一次檔案讀取，但這個檔案通常只有幾行，成本可忽略。
