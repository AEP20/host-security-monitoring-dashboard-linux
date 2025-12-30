SENSITIVE_FILES = [
    "/etc/shadow",          # Kullanıcı şifre hashleri
    "/etc/sudoers",         # Sudo yetkileri
    "/etc/passwd",          # Kullanıcı bilgileri
    "/root/.ssh/authorized_keys", 
    "/home/*/.ssh/authorized_keys",
    "/etc/ssh/sshd_config", # SSH yapılandırması
    "/var/lib/hids/config", # HIDS kendi configi
    "/etc/crontab",         # Planlanmış görevler
]

# WHITELIST
SENSITIVE_ACCESS_WHITELIST = [
    "sshd", "login", "passwd", "chfn", "chsh"
]