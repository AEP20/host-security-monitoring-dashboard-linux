# DB’den son alert’leri ve config checker sonuçlarını çeker
# Kendince bir ağırlıklandırma yapar:
# HIGH alert → -x puan
# MEDIUM → -x
# LOW → -x
# Config checker fail’leri için de eksi puanlar
# Sonunda: calculate_score() → int (0–100) döner