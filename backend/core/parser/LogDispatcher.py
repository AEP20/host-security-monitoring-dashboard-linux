"""
LogDispatcher

Görevleri:
1) Collector’dan gelen ham log satırını alır.
2) Kaynağa göre doğru parser’ı seçer.
3) Parser.match() ile satırın uyumlu olup olmadığını kontrol eder.
4) Parser.parse() ile structured event üretir.
5) Event’i veritabanına kaydeder.
6) Rule Engine’e iletilebilir dict formatında döndürür.
7) Hata durumunda sistemi asla çökertmez.
"""

from backend.core.parser.auth_parser import AuthParser
from backend.core.parser.dpkg_parser import DpkgParser
from backend.core.parser.kernel_parser import KernelParser
from backend.core.parser.sys_parser import SysParser
from backend.core.parser.ufw_parser import UfwParser

from backend.models.log_model import LogEventModel
from backend.database import SessionLocal


class LogDispatcher:

    def __init__(self):
        self.parsers = {
            "auth": AuthParser(),
            "dpkg": DpkgParser(),
            "kernel": KernelParser(),
            "syslog": SysParser(),
            "ufw": UfwParser(),
        }

    # Ana giriş

    def dispatch(self, source: str, line: str):
        """
        1) Doğru parser’ı bul
        2) Satırı parse et
        3) Event’i DB’ye kaydet
        4) Rule engine’e döndür
        """

        parser = self.parsers.get(source)
        if not parser:
            return None

        if not parser.match(line):
            return None

        try:
            event = parser.parse(line)

            self.save_to_db(event)

            return event

        except Exception as e:
            return None

    # DB write 

    def save_to_db(self, event: dict):

        session = SessionLocal()

        try:
            record = LogEventModel(
                timestamp=event.get("timestamp"),
                log_source=event.get("log_source"),
                event_type=event.get("event_type"),
                category=event.get("category"),
                severity=event.get("severity"),

                raw_log=event.get("raw"),
                message=event.get("message"),

                user=event.get("user"),
                ip_address=event.get("ip"),
                process_name=event.get("process"),

                rule_triggered=None,
                extra_data=None,
            )

            session.add(record)
            session.commit()

        except Exception as e:
            session.rollback()

        finally:
            session.close()
