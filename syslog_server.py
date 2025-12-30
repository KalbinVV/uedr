import socket
import threading
import json
import time
import logging
from incident_config import IncidentConfig

logger = logging.getLogger(__name__)


def send_notification(username: str, message: str, category: str, related_id: str = None):
    try:
        from app import db
        user_id = db.get_user_id(username)
        if user_id is not None:
            db.add_notification(user_id, message, category, related_id)
    except Exception as e:
        logger.error(f"Не удалось отправить уведомление: {e}")


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
            if start == -1 or end <= start:
                logger.debug("Сообщение не содержит JSON")
                return
            json_str = message[start:end + 1]
            payload = json.loads(json_str)
            logger.debug(f"Распаршен JSON от {source_ip}: {payload}")

            # Отправка в RabbitMQ
            from rmq_client import RMQClient
            rmq = RMQClient()
            rmq.publish_incident(payload, source_ip)

        except json.JSONDecodeError as e:
            logger.error(f"Невалидный JSON от {source_ip}: {e}")
        except Exception as e:
            logger.exception(f"Необработанное исключение при обработке от {source_ip}")

    def stop(self):
        logger.info("Остановка Syslog-сервера...")
        self.running = False
        if self.sock:
            self.sock.close()