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
RUN touch /etc/ubuntu-sys-audit-e2e
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
