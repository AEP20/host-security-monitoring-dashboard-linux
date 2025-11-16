# 6.2 core/parser – Logları anlamlı hale getiren katman

# Bu dosyaların amacı:
# Ham log satırlarını parse edip “event” nesneleri haline getirmek.

# 📁 auth_parser.py

# Girdi: auth.log satırları
# Çıktı: Örn:

# {
#   "timestamp": ...,
#   "event_type": "FAILED_LOGIN" veya "SUCCESS_LOGIN",
#   "user": "ahmet",
#   "ip": "10.0.0.1",
#   "method": "password" vs.
# }


# Kullanım:
# SSH brute force, root login, sudo misuse gibi kurallar bu event’leri kullanır.