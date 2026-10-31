# ubuntu-sys-audit

[English](README.en.md) | 繁體中文

Ubuntu 18.04、20.04、22.04、24.04、26.04 的唯讀安全檢測工具。單一靜態執行檔，下載後用 sudo 直接跑，目標主機不需要編譯器或任何套件。

## 使用方式

把 `OWNER` 換成你的 GitHub 帳號或組織。

```sh
curl -fsSLO https://github.com/OWNER/ubuntu-sys-audit/releases/latest/download/ubuntu-sys-audit-linux-amd64
curl -fsSLO https://github.com/OWNER/ubuntu-sys-audit/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
chmod +x ubuntu-sys-audit-linux-amd64
sudo ./ubuntu-sys-audit-linux-amd64
```

ARM 主機請把 `amd64` 換成 `arm64`。

### 批次掃描多台主機

沒有 TTY 時會自動輸出 JSON，所以可以直接透過 SSH 收集：

```sh
for h in web-01 web-02 db-01; do
  ssh "$h" 'sudo ./ubuntu-sys-audit-linux-amd64' > "audit-$h.json"
  echo "$h exit=$?"
done
```

上面的寫法需要主機上的 sudo 免密碼。如果 sudo 要輸入密碼，就要配置 TTY，並把報告存成檔案再取回，因為 TTY 會把 stdout 和密碼提示混在一起：

```sh
ssh -t "$h" 'sudo ./ubuntu-sys-audit-linux-amd64 --json -o audit.json > /dev/null'
scp "$h:audit.json" "audit-$h.json"
```

報告權限是 0600，擁有者會設回執行 sudo 的使用者，所以 scp 可以直接取回。

結束代碼可以直接用來判斷：

| 代碼 | 意義 |
| --- | --- |
| 0 | 沒有待處理項目 |
| 1 | 有中等級項目 |
| 2 | 有嚴重或高等級項目 |
| 130 | 掃描被中止 |

### 選項

| 選項 | 說明 |
| --- | --- |
| `--json` | 輸出 JSON 到 stdout，不開 TUI |
| `--text` | 輸出純文字到 stdout，不開 TUI |
| `--min-severity LV` | 純文字模式只列出此等級以上（預設 `medium`） |
| `-o, --output FILE` | 另外把 JSON 報告存到 FILE（權限 0600） |
| `--offline` | 不連網。沒有指定 `--oval-file` 時，不比對 CVE |
| `--oval-file PATH` | 使用本機的 OVAL 檔（`.xml` 或 `.xml.bz2`） |
| `--proxy URL` | 下載公告資料時使用的 HTTP proxy |
| `--skip-fs` | 略過全機檔案掃描 |
| `--fs-timeout TIME` | 全機檔案掃描的時間上限（預設 `5m`） |
| `--no-netlink` | 不讀取 BPF 過濾器，避免 kernel 載入 `packet_diag` |

### TUI 按鍵

`↑↓` 或 `jk` 移動 · `tab` 切換窗格 · `f` 篩選嚴重度 · `/` 搜尋 · `s` 存 JSON 到目前目錄 · `q` 離開

## 檢查項目

| 類別 | 內容 |
| --- | --- |
| CVE | 已安裝套件與執行中 kernel 比對 Ubuntu USN，包含只有 ESM 才有的修補 |
| Web | nginx、PHP 的版本與來源；非 Ubuntu 套件比對 nginx.org 與 php.net；常見危險設定；webshell 特徵；上傳目錄內的 PHP |
| 網路 | 53 Port 監聽與擁有者、連到非系統 DNS 的流量、所有監聽 Port、Packet 與 Raw socket、BPFDoor 特徵值、混雜模式、Docker |
| 程序 | 偽裝成 kernel thread 或系統服務、從暫存目錄或記憶體執行、reverse shell、Web 服務底下的 shell、挖礦程式、LD_PRELOAD、隱藏程序、已被更新但仍在使用的函式庫 |
| 完整性 | 系統執行檔與 dpkg 雜湊比對、`ld.so.preload`、隱藏的 kernel 模組、未簽章模組、PAM 模組與設定、`core_pattern`、`modprobe` 路徑 |
| 持久化 | cron、at、rc.local、init.d、profile、motd、apt hook、udev、systemd 服務、家目錄登入腳本 |
| 帳號 | 帳號數量與清單、UID 0 帳號、空白密碼、sudo 規則、高權限群組、登入紀錄、SSH 暴力嘗試 |
| SSH | `sshd_config` 有效設定、授權金鑰清單與指紋、系統帳號的金鑰、host key 權限 |
| 檔案 | SUID／SGID、Capabilities、暫存目錄的執行檔、`/dev` 內的一般檔案、任何人可寫的系統檔、非套件管理的系統執行檔 |
| 套件 | 待安裝的安全更新、apt 清單是否過舊、自動更新、apt hold、第三方來源、重要軟體版本 |
| 系統 | 版本支援期限與 ESM、kernel 版本、是否需要重開機、kernel 安全參數、CPU 漏洞緩解 |

## 設計原則

**唯讀。** 工具不會寫入任何檔案，除非你用 `-o` 或按 `s`。以 root 執行時也不會 exec 主機上的任何程式，版本是直接從執行檔內容讀出來的，不會跑 `nginx -v`。`test/e2e/run.sh` 會用 strace 驗證這一點。

已知例外：讀取 BPF 過濾器時，kernel 可能自動載入 `packet_diag` 模組，效果和執行 `ss -0` 相同。發生時報告會註明，也可以用 `--no-netlink` 關閉。

**對外連線只下載公開資料。** 連線對象是 `security-metadata.canonical.com`、`nginx.org` 和 `www.php.net`，都是單純的 GET，不會傳送主機資訊。其中 nginx.org 和 php.net 只有在發現非 Ubuntu 套件時才會連線。

**CVE 不只比版本號。** Ubuntu 會把修補 backport 到舊版本，`nginx 1.18.0` 可能早已修補，所以 apt 套件一律比對 Canonical 的 OVAL 資料。自行編譯、官方套件庫或 PPA 的版本才比對上游公告。

**對生產環境溫和。** 工具會把執行緒調成低 CPU 優先權與 idle I/O，並限制最多使用 2 個 CPU。測試時多數掃描在 5 到 60 秒內完成，下載 OVAL 較慢時最久約 2.5 分鐘；測試用容器的檔案不多，檔案很多的主機在全機掃描上會花更久（上限見 `--fs-timeout`）。

**防範來自主機的惡意內容。** 拒絕跟隨使用者目錄內的 symlink、不會被 FIFO 卡住；process 名稱與檔名內的終端機控制字元會被轉義；指令列與設定內的密碼會被遮罩；`/etc/shadow` 的雜湊讀取後立即丟棄，只保留狀態與演算法。

## 使用限制

- **未發現異常不代表主機乾淨。** 如果 kernel 已被 rootkit 控制，本機工具看到的結果都可能被竄改。隱藏程序與隱藏模組的檢查能抓到常見手法，抓不到全部。懷疑遭入侵時，請從乾淨媒體開機做離線鑑識。
- **未檢查不等於通過。** 權限不足、逾時或連不上網路的項目會標示「未檢查」，不會算成通過。
- **USN 只涵蓋 Ubuntu 已發布修補的漏洞與 apt 套件。** 還沒有修補的 CVE、snap、pip、npm、容器映像內的套件都不在比對範圍內。
- **雜湊比對的基準是本機 dpkg 資料庫。** 攻擊者若連資料庫一起改，這項就驗不出來。
- **webshell 檢查是特徵比對。** 能抓到常見樣本，抓不到客製或混淆過的版本。
- **防火牆只回報狀態。** 工具不會執行 `iptables` 或 `nft`，也看不到雲端安全群組，所以「綁定在非 loopback」不等於真的對外開放。
- **Livepatch 不會納入判斷。** kernel 項目比對的是版本，已由 Livepatch 修補的 CVE 仍可能列出。

## 無法對外連線的主機

在有網路的機器下載對應版本的 OVAL 檔，複製過去後指定：

```sh
# bionic=18.04  focal=20.04  jammy=22.04  noble=24.04  resolute=26.04
curl -fsSLO https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2
sudo ./ubuntu-sys-audit-linux-amd64 --offline --oval-file com.ubuntu.jammy.usn.oval.xml.bz2
```

資料超過 14 天時，報告會提醒你。

## 開發

```sh
make build   # 編譯到 dist/，並產生 SHA256SUMS
make test    # 單元測試（需要 Docker）
make e2e     # 每個 Ubuntu 版本都開容器、植入假後門並驗證偵測結果
```

程式只能在 Linux 上編譯，在 macOS 開發時請把編輯器的 `GOOS` 設為 `linux`，`go build` 與 `go vet` 也要加上 `GOOS=linux`。

`test/e2e/plant.sh` 會建立 UID 0 帳號與 SUID shell，只能在測試容器內執行，腳本也會拒絕在其他環境執行。

## 發布

推送 `v` 開頭的 tag，GitHub Actions 就會編譯兩種架構並建立 Release：

```sh
git tag v0.1.0 && git push origin v0.1.0
```
