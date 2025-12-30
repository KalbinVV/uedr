# incident_worker.py
import json
import sys
import os
import time
import logging

# Добавляем текущую директорию в путь (для импорта модулей)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import UserDatabase
from incident_config import IncidentConfig
from auto_responder import AutoResponder
from rmq_client import RMQClient
from salt_manager import SaltManager
from salt_script_manager import SaltScriptManager
from task_manager import TaskManager

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)-8s %(name)-12s: %(message)s',
    handlers=[
        logging.FileHandler("uedr_worker.log", encoding='utf-8'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Инициализация компонентов
db = UserDatabase("users.db")
config = IncidentConfig(db)
salt_mgr = SaltManager()
script_mgr = SaltScriptManager()
task_mgr = TaskManager()
auto_responder = AutoResponder(db, task_mgr, salt_mgr, script_mgr)

def send_notification(username: str, message: str, category: str, related_id: str = None):
    try:
        user_id = db.get_user_id(username)
        if user_id is not None:
            db.add_notification(user_id, message, category, related_id)
    except Exception as e:
        logger.error(f"Не удалось отправить уведомление: {e}")

def process_incident(payload: dict, source_ip: str, timestamp: float):
    logger.info(f"Обработка инцидента от {source_ip}")
    if timestamp is None:
        timestamp = time.time()

    # Извлечение полей согласно конфигурации
    fields = config.get_all_fields()
    extracted = {}
    for field in fields:
        key = field["field_key"]
        path = field["json_path"]
        val = config.extract_value(payload, path)
        if val is None and path == "event_src.ip":
            val = source_ip
        if path == "timestamp" and val is not None:
            try:
                timestamp = float(val)
            except (ValueError, TypeError):
                pass
        extracted[key] = val

    # Определение minion_id
    minion_id = None
    src_ip = extracted.get("src_ip")
    src_hostname = extracted.get("src_hostname")

    if salt_mgr and salt_mgr.is_available():
        try:
            all_minions = salt_mgr.get_all_minions_info()
            for m in all_minions:
                if src_ip and src_ip in m.get("ip", ""):
                    minion_id = m["id"]
                    break
            if not minion_id and src_hostname:
                for m in all_minions:
                    grains = salt_mgr.get_minion_grains(m["id"])
                    hostname = grains.get("host") or grains.get("nodename")
                    if hostname and hostname.lower() == src_hostname.lower():
                        minion_id = m["id"]
                        break
        except Exception as e:
            logger.error(f"Ошибка при сопоставлении миньона: {e}")

    if db.add_incident(json.dumps(payload, ensure_ascii=False), extracted, timestamp, minion_id):
        logger.info(f"Инцидент сохранён, ID=?, миньон: {minion_id}")

        recent = db.get_all_incidents(limit=1)
        if recent:
            incident_id = str(recent[0]["id"])
            send_notification("admin", f"Новый инцидент от {source_ip}", "incident", incident_id)

        try:
            auto_responder.evaluate_rules(extracted, minion_id)
        except Exception as e:
            logger.exception("Ошибка при обработке правил автоматической реакции")
    else:
        logger.error("Не удалось сохранить инцидент")

if __name__ == '__main__':
    logger.info("=== Запуск фонового обработчика инцидентов ===")
    rmq = RMQClient()
    rmq.consume_incidents(process_incident)