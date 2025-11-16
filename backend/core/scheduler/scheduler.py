# 6.5 core/scheduler/scheduler.py – Zamanlayıcı

# Amaç: Tüm bu collector / parser / rule engine / config checker akışını zamanla yönetmek.
# Ne yapar?
# Uygulama açıldığında scheduler başlatılır
# Belirli aralıklarla iş planlar:
# Her 10 sn → metrics_collector → DB’ye yaz
# Her 10–15 sn → logs_collector + parser + rule_engine → alert üret
# Her 30–60 dk → config_checker → sonuçları DB’ye yaz
# Kullanım:

# APScheduler olabilir
# veya

# kendi while True: time.sleep() loop’lu thread’in.