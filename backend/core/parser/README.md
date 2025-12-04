auth.log → auth_parser → parsed events
syslog → sys_parser
kernel → kernel_parser


| Dispatcher          | Input Format            | Çıkış                               |
| ------------------- | ----------------------- | ----------------------------------- |
| **LogDispatcher**   | *Raw log line* (string) | parsed event + DB yazımı            |
| **EventDispatcher** | *Structured event dict* | DB yazımı + rule engine integration |
