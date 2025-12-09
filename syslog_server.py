# syslog_server.py
import socket
import threading
import json
import time
import logging
from incident_config import IncidentConfig

logger = logging.getLogger(__name__)

class SyslogUDPServer:
    def __init__(self, db, config: IncidentConfig, salt_mgr, auto_responder, host='0.0.0.0', port=514):
        self.db = db
        self.config = config
        self.salt_mgr = salt_mgr
        self.auto_responder = auto_responder
        self.host = host
        self.port = port
        self.sock = None
        self.running = False

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        logger.info(f"Syslog-сервер запущен на {self.host}:{self.port} (UDP)")

    def _run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            logger.info("UDP-сокет успешно привязан")
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    message = data.decode('utf-8', errors='ignore').strip()
                    logger.debug(f"Получено сообщение от {addr[0]}: {message[:100]}...")
                    self._handle_message(message, addr[0])
                except Exception as e:
                    logger.error(f"Ошибка при получении данных: {e}")
        except Exception as e:
            logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА: не удалось запустить сервер: {e}")
        finally:
            if self.sock:
                self.sock.close()
                logger.info("UDP-сокет закрыт")

    def _handle_message(self, message: str, source_ip: str):
        try:
            start = message.find('{')
            end = message.rfind('}')
            if start == -1 or end == -1 or end <= start:
                logger.debug("Сообщение не содержит JSON")
                return

            json_str = message[start:end+1]
            payload = json.loads(json_str)
            logger.debug(f"Распаршен JSON: {payload}")

            fields = self.config.get_all_fields()
            extracted = {}
            timestamp = time.time()

            for field in fields:
                key = field["field_key"]
                path = field["json_path"]
                val = self.config.extract_value(payload, path)
                if val is None and path == "event_src.ip":
                    val = source_ip
                if path == "timestamp" and val is not None:
                    try:
                        timestamp = float(val)
                    except (ValueError, TypeError):
                        pass
                extracted[key] = val

            # Определение миньона
            minion_id = None
            src_ip = extracted.get("src_ip")
            src_hostname = extracted.get("src_hostname")

            if self.salt_mgr and self.salt_mgr.is_available():
                try:
                    all_minions = self.salt_mgr.get_all_minions_info()
                    for m in all_minions:
                        if src_ip and src_ip in m.get("ip", ""):
                            minion_id = m["id"]
                            break
                        if src_hostname:
                            grains = self.salt_mgr.get_minion_grains(m["id"])
                            hostname = grains.get("host") or grains.get("nodename")
                            if hostname and hostname.lower() == src_hostname.lower():
                                minion_id = m["id"]
                                break
                except Exception as e:
                    logger.error(f"Ошибка при сопоставлении миньона: {e}")

            # Сохраняем инцидент
            if self.db.add_incident(json_str, extracted, timestamp, minion_id):
                logger.info(f"Инцидент принят от {source_ip}, привязан к миньону: {minion_id}")
                # Автоматическая реакция
                try:
                    self.auto_responder.evaluate_rules(extracted, minion_id)
                except Exception as e:
                    logger.exception("Ошибка при обработке правил автоматической реакции")
            else:
                logger.error("Не удалось сохранить инцидент")

        except json.JSONDecodeError as e:
            logger.error(f"Невалидный JSON от {source_ip}: {e}")
        except Exception as e:
            logger.exception(f"Необработанное исключение при обработке от {source_ip}")

    def stop(self):
        logger.info("Остановка Syslog-сервера...")
        self.running = False
        if self.sock:
            self.sock.close()