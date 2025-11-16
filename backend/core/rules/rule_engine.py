# #parsed event → rule_engine → triggered rule → alert_model.save()

# 📁 rule_engine.py
# Bu dosya orkestratör.
# Görevleri:
# Tüm event’leri (auth, sys, kernel, dpkg, process, port) input olarak alır
# Her kural modülünü tek tek çağırır:
# ssh_bruteforce.check(events)
# root_login.check(events)
# suspicious_process.check(process_list)
# Her kural bir şey bulduğunda Alert nesnesi döner
# Bu alert’ler:
# DB’ye kaydedilir (AlertModel)
# Belki loglanır
# Rule engine’in ana fonksiyonu gibi bir şey hayal et:

# def run_all_rules(parsed_events, system_state):
#     alerts = []
#     for rule in RULES:
#         alerts.extend(rule.check(parsed_events, system_state))
#     return alerts