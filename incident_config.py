# incident_config.py
import logging

logger = logging.getLogger(__name__)

class IncidentConfig:
    def __init__(self, db):
        self.db = db

    def get_all_fields(self):
        return self.db.get_incident_fields()

    def save_fields(self, fields):
        return self.db.save_incident_fields(fields)

    @staticmethod
    def extract_value(payload: dict, json_path: str):
        if not json_path or not isinstance(payload, dict):
            return None
        keys = json_path.split('.')
        value = payload
        try:
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return None
            return value
        except Exception as e:
            logger.debug(f"Ошибка извлечения значения по пути '{json_path}': {e}")
            return None