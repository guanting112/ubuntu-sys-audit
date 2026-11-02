#!/bin/sh
# End to end test: boots a disposable systemd "host" in Docker for each Ubuntu
# release, scans it clean, plants fake indicators, scans again and checks the
# detections, then uses strace to confirm the audit executes nothing and writes
# nothing. Everything happens inside throwaway containers.
#
#   test/e2e/run.sh                 all releases
#   test/e2e/run.sh 22.04 24.04     chosen releases
set -u
cd "$(dirname "$0")/../.." || exit 1

case "$(uname -m)" in
arm64 | aarch64) arch=arm64 ;;
*) arch=amd64 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=e2e" -o "$work/audit" . || exit 1
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$work/fakeimplant" ./test/e2e/fakeimplant || exit 1
# A real but old Caddy release, for the checks that read Go build information.
# It is renamed so the clean scan does not find it where Caddy is looked for.
caddy_version=2.6.4
curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v$caddy_version/caddy_${caddy_version}_linux_$arch.tar.gz" | tar -xz -C "$work" caddy || exit 1
mv "$work/caddy" "$work/caddy-e2e"
cp test/e2e/plant.sh test/e2e/assert.py "$work/"
chmod -R a+rX "$work"

[ $# -gt 0 ] || set -- 18.04 20.04 22.04 24.04 26.04
status=0
for release in "$@"; do
	echo "=== Ubuntu $release ($arch)"
	name="usa-e2e-run-$release"
	docker build -q --build-arg "RELEASE=$release" -t "usa-e2e:$release" test/e2e >/dev/null || { status=1; continue; }
	docker rm -f "$name" >/dev/null 2>&1
	docker run -d --name "$name" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
		-v "$work:/opt/e2e:ro" "usa-e2e:$release" >/dev/null || { status=1; continue; }
	sleep 12
	# Remove the markers that make the audit treat this as a container, so it
	# applies the same rules it uses on a real host.
	docker exec "$name" sh -c 'rm -f /.dockerenv /run/.containerenv /run/systemd/container'

	# Real hosts run udevd, whose argv[0] differs from its binary from 22.04 on.
	# Containers do not start it, which once hid a false positive on every host.
	docker exec "$name" sh -c 'pgrep -x systemd-udevd >/dev/null || /lib/systemd/systemd-udevd --daemon >/dev/null 2>&1; sleep 1; pgrep -x systemd-udevd >/dev/null' \
		|| { echo "  FAIL udevd is not running, so the clean scan would not test it"; status=1; }

	docker exec "$name" sh -c '/opt/e2e/audit --json >/root/clean.json 2>/dev/null; python3 /opt/e2e/assert.py clean /root/clean.json' || status=1

	docker exec "$name" sh /opt/e2e/plant.sh >/dev/null 2>&1
	# Run from /tmp, the way people often do, to confirm the tool ignores itself.
	docker exec "$name" sh -c 'cp /opt/e2e/audit /tmp/audit; /tmp/audit --json >/root/dirty.json 2>/dev/null; python3 /opt/e2e/assert.py planted /root/dirty.json' 2>/dev/null || status=1

	# --cve answers single CVEs, including ones with no fix yet. The kernel here
	# is OrbStack's, not Ubuntu's, so a kernel-only CVE must say so instead of
	# reading as not affected.
	docker exec "$name" sh -c '
		/opt/e2e/audit --cve CVE-2024-6387,CVE-2026-98432 --json >/root/lookup.json 2>/dev/null
		python3 /opt/e2e/assert.py lookup /root/lookup.json || exit 1
		/opt/e2e/audit --cve not-a-cve >/dev/null 2>&1; code=$?
		[ "$code" = 64 ] || { echo "  FAIL an invalid --cve value exited $code"; exit 1; }
	' 2>/dev/null || status=1

	# -o must refuse paths that would give a limited sudo user control of a file,
	# without losing the report or the exit code for the critical findings.
	docker exec "$name" sh -c '
		cp /etc/issue /root/issue.bak
		SUDO_UID=1000 SUDO_GID=1000 /opt/e2e/audit --json --offline --skip-fs -o /etc/issue >/root/o.json 2>/dev/null; code=$?
		cmp -s /etc/issue /root/issue.bak || { echo "  FAIL -o overwrote an existing file"; exit 1; }
		[ "$code" = 2 ] || { echo "  FAIL a failed -o changed the exit code to $code"; exit 1; }
		[ -s /root/o.json ] || { echo "  FAIL a failed -o lost the report on stdout"; exit 1; }
		SUDO_UID=1000 SUDO_GID=1000 /opt/e2e/audit --json --offline --skip-fs -o /etc/new-report.json >/dev/null 2>&1
		[ ! -e /etc/new-report.json ] || { echo "  FAIL -o created a file in a directory the sudo user cannot write to"; exit 1; }
		/opt/e2e/audit --json --offline --skip-fs -o /root/own.json >/dev/null 2>&1
		[ "$(stat -c %a /root/own.json)" = 600 ] || { echo "  FAIL report is not mode 600"; exit 1; }
		echo "  -o: refused unsafe paths, kept exit 2, report mode 600"
	' 2>/dev/null || status=1

	docker exec "$name" sh -c '
		strace -f -qq -o /root/st.txt \
			-e trace=execve,execveat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,chmod,fchmod,fchmodat,chown,fchown,fchownat,truncate,ftruncate,symlink,symlinkat,link,linkat,mknod,mknodat,setxattr,fsetxattr,lsetxattr,mount,umount2,init_module,finit_module,delete_module,openat \
			/opt/e2e/audit --json --offline >/dev/null 2>&1
		execs=$(grep -cE "execve(at)?\(" /root/st.txt)
		writes=$(grep openat /root/st.txt | grep -cE "O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")
		mutate=$(grep -cE "^[0-9]+ +(unlink|rename|mkdir|rmdir|chmod|fchmod|chown|fchown|truncate|ftruncate|symlink|link|mknod|setxattr|fsetxattr|lsetxattr|mount|umount|init_module|finit_module|delete_module)" /root/st.txt)
		echo "  strace: execve=$execs (1 expected) writes=$writes mutating=$mutate"
		[ -e /tmp/AUDIT-EXECUTED-A-HOST-BINARY ] && { echo "  FAIL audit executed a host binary"; exit 1; }
		[ "$execs" = 1 ] && [ "$writes" = 0 ] && [ "$mutate" = 0 ]
	' 2>/dev/null || { echo "  FAIL read only check"; status=1; }
	docker rm -f "$name" >/dev/null 2>&1
done
[ "$status" = 0 ] && echo "ALL PASSED" || echo "FAILED"
exit "$status"
