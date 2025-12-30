# incident_worker_thread.py
import threading
import json
import time
import logging

from rmq_client import RMQClient

logger = logging.getLogger(__name__)


class IncidentWorkerThread:
    def __init__(self, db, config, salt_mgr, auto_responder):
        self.db = db
        self.config = config
        self.salt_mgr = salt_mgr
        self.auto_responder = auto_responder
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("IncidentWorkerThread запущен")

    def _run(self):
        rmq = RMQClient()
        def process_incident(payload, source_ip, timestamp):
            self._process_incident_internal(payload, source_ip, timestamp)
        try:
            rmq.consume_incidents(process_incident)
        except Exception as e:
            logger.exception("IncidentWorkerThread завершил работу с ошибкой")

    def _process_incident_internal(self, payload: dict, source_ip: str, timestamp: float):
        logger.info(f"Обработка инцидента из RMQ от {source_ip}")
        if timestamp is None:
            timestamp = time.time()

        # Получаем конфигурацию полей
        fields = self.config.get_all_fields()
        src_ip_path = None
        src_hostname_path = None
        for field in fields:
            if field["field_key"] == "src_ip":
                src_ip_path = field["json_path"]
            elif field["field_key"] == "src_hostname":
                src_hostname_path = field["json_path"]

        extracted = {}
        for field in fields:
            key = field["field_key"]
            path = field["json_path"]
            val = self.config.extract_value(payload, path)
            if val is None and path == src_ip_path:
                val = source_ip
            if path == "timestamp" and val is not None:
                try:
                    timestamp = float(val)
                except (ValueError, TypeError):
                    pass
            extracted[key] = val

        minion_id = None

        src_ip = extracted.get("src_ip")
        src_hostname = extracted.get("src_hostname")

        if self.salt_mgr and self.salt_mgr.is_available():
            try:
                all_minions = self.salt_mgr.get_all_minions_info()

                # Поиск по IP
                if src_ip:
                    for m in all_minions:
                        ip_list = m.get("ip", "")
                        if src_ip in ip_list:
                            minion_id = m["id"]
                            break

                # Если не найден — по hostname
                if not minion_id and src_hostname:
                    src_hostname_lower = src_hostname.lower()
                    for m in all_minions:
                        try:
                            grains = self.salt_mgr.get_minion_grains(m["id"])
                            hostname = grains.get("host") or grains.get("nodename")
                            if hostname and hostname.lower() == src_hostname_lower:
                                minion_id = m["id"]
                                break
                        except Exception as e:
                            logger.debug(f"Не удалось получить grains для {m['id']}: {e}")
                            continue

            except Exception as e:
                logger.error(f"Ошибка при сопоставлении миньона: {e}")

        # Сохранение в БД
        if self.db.add_incident(json.dumps(payload, ensure_ascii=False), extracted, timestamp, minion_id):
            logger.info(f"Инцидент сохранён, миньон: {minion_id}")
            recent_incidents = self.db.get_all_incidents(limit=1)
            if recent_incidents:
                incident_id = str(recent_incidents[0]["id"])
                self._send_notification("admin", f"Новый инцидент от {source_ip}", "incident", incident_id)

            # Автоматическое реагирование
            try:
                self.auto_responder.evaluate_rules(extracted, minion_id)
            except Exception as e:
                logger.exception("Ошибка при обработке правил автоматической реакции")
        else:
            logger.error("Не удалось сохранить инцидент")

    def _send_notification(self, username: str, message: str, category: str, related_id: str = None):
        try:
            user_id = self.db.get_user_id(username)
            if user_id is not None:
                self.db.add_notification(user_id, message, category, related_id)
        except Exception as e:
            logger.error(f"Не удалось отправить уведомление: {e}")

    def stop(self):
        logger.info("Остановка IncidentWorkerThread...")
        self.running = False