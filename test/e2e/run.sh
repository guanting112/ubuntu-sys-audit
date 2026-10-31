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

	docker exec "$name" sh -c '/opt/e2e/audit --json >/root/clean.json 2>/dev/null; python3 /opt/e2e/assert.py clean /root/clean.json' || status=1

	docker exec "$name" sh /opt/e2e/plant.sh >/dev/null 2>&1
	docker exec "$name" sh -c 'rm -f /etc/ld.so.preload.keep; /opt/e2e/audit --json >/root/dirty.json 2>/dev/null; python3 /opt/e2e/assert.py planted /root/dirty.json' 2>/dev/null || status=1

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
