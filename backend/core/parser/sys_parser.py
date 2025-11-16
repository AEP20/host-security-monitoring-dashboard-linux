# 📁 sys_parser.py

# Girdi: syslog satırları
# Çıktı: “SERVICE_FAILED”, “SYSTEM_WARNING” gibi event’ler.

# Ör:

# {
#   "timestamp": ...,
#   "event_type": "SERVICE_FAILED",
#   "service": "nginx",
#   "message": "failed to start"
# }