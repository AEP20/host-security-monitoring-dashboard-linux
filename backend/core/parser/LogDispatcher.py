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

from backend.core.storage import services

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
        """
        DB write işlemi artık doğrudan yapılmaz,
        event DBWriter queue'suna bırakılır.
        """

        try:
            event["type"] = "LOG_EVENT"
            services.db_writer.enqueue(event)
        except Exception:
            pass
