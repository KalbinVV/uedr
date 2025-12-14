import logging
from typing import Dict

logger = logging.getLogger(__name__)


def _send_notification(username: str, message: str, category: str, related_id: str = None):
    try:
        from app import db
        user_id = db.get_user_id(username)
        if user_id is not None:
            db.add_notification(user_id, message, category, related_id)
    except Exception as e:
        logger.error(f"Не удалось отправить уведомление из авто-респондера: {e}")


class AutoResponder:
    def __init__(self, db, task_manager, salt_mgr, script_mgr):
        self.db = db
        self.task_manager = task_manager
        self.salt_mgr = salt_mgr
        self.script_mgr = script_mgr

    def evaluate_rules(self, incident_data: dict, minion_id: str = None):
        if not minion_id:
            logger.debug("Инцидент не привязан к миньону — пропуск правил")
            return

        try:
            rules = self.db.get_all_rules()
            for rule in rules:
                if not rule.get("enabled"):
                    continue
                if self._rule_matches(rule, incident_data):
                    logger.info(f"Правило '{rule['name']}' сработало на инцидент")
                    self._execute_action(rule, minion_id, incident_data)
        except Exception as e:
            logger.exception(f"Ошибка при оценке правил: {e}")

    def _rule_matches(self, rule: dict, incident_data: dict) -> bool:
        conditions = rule.get("conditions", [])
        if not conditions:
            return False

        logic = rule.get("logic", "AND")
        matches = []
        for cond in conditions:
            field_key = cond["field_key"]
            expected_value = cond["value"]
            actual_value = incident_data.get(field_key)
            matches.append(str(actual_value) == str(expected_value))

        if logic == "AND":
            return all(matches)
        else:
            return any(matches)

    def _execute_action(self, rule: dict, minion_id: str, incident_data: dict):
        script_name = rule["script_name"]
        from uuid import uuid4
        task_id = str(uuid4())

        def _run_task():
            logger = logging.getLogger(__name__)
            try:
                logger.debug(f"[Авто] Рендеринг сценария '{script_name}' с контекстом")
                temp_path = self.script_mgr.render_script(script_name, incident_data)
                raw_result = self.salt_mgr.apply_rendered_state(minion_id, temp_path)
                return {
                    "minion": minion_id,
                    "state": script_name,
                    "details": raw_result
                }
            except Exception as e:
                logger.exception(
                    f"[Авто] Ошибка при применении сценария '{script_name}' к '{minion_id}'"
                )
                return {
                    "minion": minion_id,
                    "state": script_name,
                    "error": str(e)
                }

        self.task_manager.submit_task(task_id, _run_task)
        logger.info(f"Запущен сценарий '{script_name}' на миньоне '{minion_id}' по правилу")
        _send_notification(
            "admin",
            f"Правило '{rule['name']}' сработало на миньоне {minion_id}",
            "rule",
            str(rule['id'])
        )

    @staticmethod
    def _run_salt_state_wrapped(salt_mgr, minion_id: str, state_name: str):
        try:
            logger = logging.getLogger(__name__)
            logger.debug(f"[Авто] Применение state '{state_name}' к '{minion_id}'")
            result = salt_mgr.apply_state(minion_id, state_name)
            return result
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.exception(
                f"[Авто] Ошибка при применении сценария '{state_name}' к '{minion_id}'"
            )
            return {"error": str(e)}