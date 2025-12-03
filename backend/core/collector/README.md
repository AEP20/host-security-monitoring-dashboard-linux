metrics_collector → json
logs_collector → lines
processes_collector → psutil output
network_collector → open ports

<!-- | Collector      | Önerilen Zaman          |
| -------------- | ----------------------- |
| metrics        | 60 sn                   |
| processes      | 10–30 sn                |
| network        | 10 sn                   |
| logs           | 2 sn (en hızlı büyüyen) |
| config checker | 15–30 dk                | -->


<!-- | Collector | Veri tipi  | Parsing    | Rule Engine            | DB                  |
| --------- | ---------- | ---------- | ---------------------- | ------------------- |
| Logs      | ham text   | ✔️ gerekli | ✔️                     | log_events          |
| Metrics   | structured | ❌          | ✔️ (usage alert)       | metrics             |
| Network   | structured | ❌          | ✔️ (port exposure)     | network_connections |
| Process   | structured | ❌          | ✔️ (malicious process) | processes           | -->


<!-- | Collector            | Parser var mı? | DB’ye yazar mı?   | Rule Engine kullanır mı?   |
| -------------------- | -------------- | ----------------- | -------------------------- |
| **LogCollector**     | ✔ Evet         | ✔ Evet            | ✔ Evet                     |
| **MetricsCollector** | ✖ Hayır        | ✔ Snapshot yazar  | ✔ Evet                     |
| **ProcessCollector** | ✖ Hayır        | ✖ Snapshot yazmaz | ✔ Evet (snapshot kullanır) |
| **NetworkCollector** | ✖ Hayır        | ✖ Snapshot yazmaz | ✔ Evet (snapshot kullanır) | -->
