# Disposable "host": systemd as PID 1 with sshd, nginx, php-fpm and cron, so the
# audit runs against the same services it sees on a real Ubuntu server.
ARG RELEASE=24.04
FROM ubuntu:${RELEASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv udev dbus cron rsyslog openssh-server sudo \
        nginx php-fpm unattended-upgrades libcap2-bin iproute2 strace tmux python3 curl ca-certificates \
    && (apt-get install -y --no-install-recommends systemd-resolved || true) \
    && systemctl enable ssh cron nginx 2>/dev/null || true
# Databases and runtimes from Ubuntu's archive, so the stack check meets real
# packages and services. MySQL and MariaDB conflict, so releases alternate,
# and Valkey is added only where it installs without removing Redis. 18.04
# gets neither: its MySQL 5.7 grew to 5.8 GB in this container and was OOM
# killed in a loop, which a real 18.04 server does not do. apt
# keeps its lists uncompressed, as on a real server, where the stack check
# reads them to tell Ubuntu's packages from other repositories'.
ARG RELEASE
RUN rm -f /etc/apt/apt.conf.d/docker-gzip-indexes && rm -rf /var/lib/apt/lists/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql redis-server sqlite3 nodejs \
    && case "$RELEASE" in 18.04) db= ;; 20.04|24.04) db=mariadb-server ;; *) db=mysql-server ;; esac \
    && { [ -z "$db" ] || apt-get install -y --no-install-recommends "$db"; } \
    && (apt-get install -y --no-install-recommends --no-remove valkey-server || true)
RUN touch /etc/ubuntu-sys-audit-e2e
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
