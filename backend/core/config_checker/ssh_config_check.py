# ssh_config_check.py

# /etc/ssh/sshd_config okuyup:
# PermitRootLogin
# PasswordAuthentication
# MaxAuthTries
# gibi parametreleri kontrol eder.
# Çıktı örn:

# [
#   {"name": "PermitRootLogin", "status": "fail", "severity": "HIGH"},
#   {"name": "PasswordAuthentication", "status": "warn", "severity": "MEDIUM"}
# ]