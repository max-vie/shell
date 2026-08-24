#!/bin/sh
set -eu

# This script runs inside a Debian image through virt-customize. OpenTofu's
# Proxmox initialization supplies per-guest hostname and network values later.
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = debian ] || {
  printf 'Unsupported guest OS: %s\n' "${ID:-unknown}" >&2
  exit 1
}

if ! id -u init >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --groups sudo init
fi
usermod --append --groups sudo init
passwd --lock init

install -d -m 0700 -o init -g init /home/init/.ssh
# This broad rule is a temporary automation boundary. SUDO must replace it
# with a narrower account contract before the image is used for services.
cat >/etc/sudoers.d/init <<'EOF'
init ALL=(ALL) NOPASSWD: ALL
EOF
chown root:root /etc/sudoers.d/init
chmod 0440 /etc/sudoers.d/init
visudo -cf /etc/sudoers.d/init

install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/60-init-key-only.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
chown root:root /etc/ssh/sshd_config.d/60-init-key-only.conf
chmod 0644 /etc/ssh/sshd_config.d/60-init-key-only.conf
install -d -m 0755 /run/sshd
sshd -t

install -d -m 0755 /usr/local/sbin /var/lib/init
cat >/usr/local/sbin/init-image-firstboot <<'EOF'
#!/bin/sh
set -eu
ssh-keygen -A
install -d -m 0755 /var/lib/init
printf 'image-firstboot=complete\n' >/var/lib/init/image-ready
chmod 0644 /var/lib/init/image-ready
EOF
chmod 0755 /usr/local/sbin/init-image-firstboot
chown root:root /usr/local/sbin/init-image-firstboot

cat >/etc/systemd/system/init-image-firstboot.service <<'EOF'
[Unit]
Description=Complete the first boot of the prepared SHELL image
After=local-fs.target
Before=ssh.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/init-image-firstboot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chown root:root /etc/systemd/system/init-image-firstboot.service
chmod 0644 /etc/systemd/system/init-image-firstboot.service

systemctl --root=/ enable ssh.service qemu-guest-agent.service init-image-firstboot.service
