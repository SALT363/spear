# Spear

![image](docs/assets/pear.png)

## Features

- **Core:**
    - 🔩 Extensible config loader.
    - 🚐 Flexible event bus (external modules)
    - 📦 Cached shared file watcher.
    - 🧩 Runtime plugin loader.
- **API:**
    - 📡 Integrated logger. Easy to log plugin events.
    - 🧩 Rich plugin API.
    - ⌛ Timewindow API.
    - 🌩 Trigger registry.
    - 📋 Module registry.
- **Modules:**
    - 🔐 Authwatch: Watch for unsuccess/success login access and sudo request.
        - Supports: SSH, FTP, HTTP, Sudo.
        - Configurable hits and timewindow.
        - Support fallback log file for multiple OS compatibility (Debian, Arch, Fedora)
    - 🔦 VerticalScan: Watch for vertical port scanning
        - Detects SYN scan, FIN scan, Xmas tree, Null scan, Fragmented packets.
        - Configurable hits and timewindow.
- **Triggers:**
    - 👁 Logs: Log all activity to .csv, .json or .log file.

## To-do

- [ ] More modules (flooding, suspicious TTL, IP source routing, fragmented spoofing, DNS tunneling, more authwatch protocols: RDP, FTP, SMTP, MySQL..., heuristic, iptables/nftables integration, syslog)
- [ ] More triggers (email/SMTP, Discord, Telegram, Slack)
- [ ] A dashboard? (ELK stack, Grafana, Prometheus)
- [ ] Critical integrity check (/etc/passwd, /etc/shadow) log changes and more
- [ ] AIDE hash check
- [ ] Detect suspicious processes (nc -l, bash -i >&, reverse shell-like commands)
- [ ] Detect weird cwd processes (/tmp, /dev/shm)
- [ ] Check loaded modules (lsmod)
- [ ] Monitor changes on cron, systemd services and bashrc file (check for persistence)
- [ ] Detect bad behavior (user creation, UID 0 assigned to non-root users)
- [ ] Detect key abuse (new keys on .ssh/authorized_keys)
- [ ] Check bad permission misconfigurations (.ssh or root with unsafe permission flags)
- [ ] Filesystem traps (/root/secret.txt) and fake files, report if file is read
- [ ] Misconfigured servers (MySQL and critical services running on 0.0.0.0)
- [ ] Documentation
- [ ] Better README file
- [ ] Kasane Teto references
