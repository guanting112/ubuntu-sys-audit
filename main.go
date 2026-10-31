// ubuntu-sys-audit is a read only security audit for Ubuntu 18.04 to 26.04,
// distributed as one static binary. It is meant to be downloaded and run with
// sudo: it needs no compiler, no packages and leaves nothing on the host.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"

	"ubuntu-sys-audit/internal/checks"
	"ubuntu-sys-audit/internal/model"
	"ubuntu-sys-audit/internal/output"
	"ubuntu-sys-audit/internal/tui"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `ubuntu-sys-audit：Ubuntu 18.04 到 26.04 的唯讀安全檢測工具

用法：
  sudo ./ubuntu-sys-audit [選項]

有終端機時開啟 TUI。沒有 TTY 時（例如 ssh host 'sudo ./ubuntu-sys-audit'）自動輸出 JSON。

選項：
  --json               輸出 JSON 到 stdout，不開 TUI
  --text               輸出純文字到 stdout，不開 TUI
  --min-severity LV    純文字模式只列出此等級以上：critical、high、medium、info、ok、skipped（預設 medium）
  -o, --output FILE    另外把 JSON 報告存到 FILE（權限 0600）
  --offline            不連網。沒有指定 --oval-file 時，不比對 CVE
  --oval-file PATH     使用本機的 OVAL 檔（.xml 或 .xml.bz2），給無法對外連線的主機使用
  --proxy URL          下載公告資料時使用的 HTTP proxy
  --skip-fs            略過全機檔案掃描（SUID、Capabilities、暫存目錄）
  --fs-timeout TIME    全機檔案掃描的時間上限（預設 5m）
  --no-netlink         不讀取 BPF 過濾器，避免 kernel 自動載入 packet_diag 模組
  --version            顯示版本

結束代碼：0 無待處理項目，1 有中等級項目，2 有嚴重或高等級項目，130 掃描被中止
`

func main() {
	os.Exit(run())
}

func run() int {
	var (
		asJSON, asText, offline, skipFS, noNetlink, showVersion bool
		outPath, ovalFile, proxy, minSev                        string
		fsTimeout                                               time.Duration
	)
	fs := flag.NewFlagSet("ubuntu-sys-audit", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.BoolVar(&asJSON, "json", false, "")
	fs.BoolVar(&asText, "text", false, "")
	fs.StringVar(&minSev, "min-severity", "medium", "")
	fs.StringVar(&outPath, "output", "", "")
	fs.StringVar(&outPath, "o", "", "")
	fs.BoolVar(&offline, "offline", false, "")
	fs.StringVar(&ovalFile, "oval-file", "", "")
	fs.StringVar(&proxy, "proxy", "", "")
	fs.BoolVar(&skipFS, "skip-fs", false, "")
	fs.DurationVar(&fsTimeout, "fs-timeout", 5*time.Minute, "")
	fs.BoolVar(&noNetlink, "no-netlink", false, "")
	fs.BoolVar(&showVersion, "version", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 64
	}
	if showVersion {
		fmt.Printf("ubuntu-sys-audit %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	}
	threshold, ok := parseSeverity(minSev)
	if !ok {
		fmt.Fprintf(os.Stderr, "--min-severity 的值無效：%s\n", minSev)
		return 64
	}

	// Two threads of work is enough, and keeps the scan from competing with
	// production traffic on the host being audited.
	if runtime.NumCPU() > 2 {
		runtime.GOMAXPROCS(2)
	}

	opts := checks.Options{
		Version: version, Offline: offline, OVALFile: ovalFile, Proxy: proxy,
		SkipFS: skipFS, NoNetlink: noNetlink, FSTimeout: fsTimeout,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interactive := !asJSON && !asText && isTerminal(os.Stdin) && isTerminal(os.Stdout)
	if interactive {
		report, err := tui.Run(ctx, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "TUI 錯誤：", err)
			return 70
		}
		if report == nil {
			fmt.Fprintln(os.Stderr, "掃描已中止。")
			return 130
		}
		fmt.Println(output.Summary(report))
		if outPath != "" {
			if err := output.SaveJSON(outPath, report); err != nil {
				fmt.Fprintln(os.Stderr, "無法寫入報告：", err)
				return 74
			}
			fmt.Println("報告已存到", outPath)
		}
		return report.ExitCode()
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "注意：沒有以 root 執行，部分項目未檢查。請用 sudo 執行。")
	}
	report := checks.Run(ctx, opts, nil)
	if outPath != "" {
		if err := output.SaveJSON(outPath, report); err != nil {
			fmt.Fprintln(os.Stderr, "無法寫入報告：", err)
			return 74
		}
	}
	if asText {
		output.Text(os.Stdout, report, threshold)
	} else {
		if err := output.JSON(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, "無法輸出 JSON：", err)
			return 74
		}
	}
	if ctx.Err() != nil {
		return 130
	}
	return report.ExitCode()
}

func parseSeverity(s string) (model.Severity, bool) {
	for _, sev := range model.AllSeverities {
		if strings.EqualFold(s, sev.String()) {
			return sev, true
		}
	}
	return model.Medium, false
}

// isTerminal asks the kernel, because a character device check would also
// accept /dev/null, which is what stdin and stdout are under cron and most
// deployment tools.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(f.Fd())
}
