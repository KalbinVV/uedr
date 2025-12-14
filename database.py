import sqlite3
import logging
import time
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)


class UserDatabase:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    minion_id TEXT,
                    raw_data TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_attributes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    field_key TEXT NOT NULL,
                    value TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_fields (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    display_name TEXT NOT NULL,
                    field_key TEXT UNIQUE NOT NULL,
                    json_path TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    logic TEXT NOT NULL CHECK(logic IN ('AND', 'OR')),
                    script_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_conditions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    field_key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    FOREIGN KEY (rule_id) REFERENCES auto_rules(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    category TEXT NOT NULL,
                    related_id TEXT,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            conn.commit()

    def add_user(self, username: str, password_hash: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> Optional[Tuple[int, str, str]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            )
            return cursor.fetchone()

    def add_notification(self, user_id: int, message: str, category: str, related_id: str = None):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO notifications (user_id, message, category, related_id, is_read, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                """, (user_id, message, category, related_id, time.time()))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Ошибка добавления уведомления: {e}")
            return None

    def get_user_id(self, username: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return row[0] if row else None

    def get_unread_notifications(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, message, category, related_id, created_at
                FROM notifications
                WHERE user_id = ? AND is_read = 0
                ORDER BY created_at DESC
            """, (user_id,))
            return [dict(row) for row in cursor.fetchall()]

    def mark_notification_as_read(self, notification_id: int, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
                (notification_id, user_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def mark_all_notifications_as_read(self, user_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
            conn.commit()

    def get_incident_fields(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT display_name, field_key, json_path FROM incident_fields ORDER BY id"
            )
            return [dict(row) for row in cursor.fetchall()]

    def save_incident_fields(self, fields: List[Dict]) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM incident_fields")
                for field in fields:
                    conn.execute(
                        "INSERT INTO incident_fields (display_name, field_key, json_path) VALUES (?, ?, ?)",
                        (field["display_name"], field["field_key"], field["json_path"])
                    )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка сохранения полей: {e}")
            return False

    def add_incident(
            self,
            raw_json: str,
            extracted_values: Dict[str, str],
            timestamp: float,
            minion_id: str = None
    ) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO incidents (timestamp, minion_id, raw_data) VALUES (?, ?, ?)",
                    (timestamp, minion_id, raw_json)
                )
                incident_id = cursor.lastrowid
                for key, value in extracted_values.items():
                    cursor.execute(
                        "INSERT INTO incident_attributes (incident_id, field_key, value) VALUES (?, ?, ?)",
                        (incident_id, key, str(value) if value is not None else "")
                    )
                conn.commit()
                logger.info(f"Инцидент сохранён, ID={incident_id}, миньон={minion_id}")
                return True
        except Exception as e:
            logger.error(f"Ошибка сохранения инцидента: {e}")
            return False

    def get_all_incidents(self, limit: int = 100) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, minion_id, raw_data FROM incidents
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                incidents = []
                for row in cursor.fetchall():
                    incident = {
                        "id": row["id"],
                        "timestamp": row["timestamp"],
                        "minion_id": row["minion_id"],
                        "raw_data": row["raw_data"]
                    }
                    cursor2 = conn.cursor()
                    cursor2.execute(
                        "SELECT field_key, value FROM incident_attributes WHERE incident_id = ?",
                        (row["id"],)
                    )
                    for attr in cursor2.fetchall():
                        incident[attr["field_key"]] = attr["value"]
                    incidents.append(incident)
                return incidents
        except Exception as e:
            logger.error(f"Ошибка получения инцидентов: {e}")
            return []

    def get_all_rules(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, logic, script_name, enabled FROM auto_rules ORDER BY id"
            )
            rules = []
            for row in cursor.fetchall():
                rule = dict(row)
                cursor2 = conn.cursor()
                cursor2.execute(
                    "SELECT field_key, value FROM rule_conditions WHERE rule_id = ?",
                    (rule["id"],)
                )
                rule["conditions"] = [dict(cond) for cond in cursor2.fetchall()]
                rules.append(rule)
            return rules

    def save_rule(
            self,
            name: str,
            logic: str,
            script_name: str,
            conditions: list,
            enabled: bool = True
    ) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO auto_rules (name, logic, script_name, enabled) VALUES (?, ?, ?, ?)",
                    (name, logic, script_name, int(enabled))
                )
                rule_id = cursor.lastrowid
                for cond in conditions:
                    cursor.execute(
                        "INSERT INTO rule_conditions (rule_id, field_key, value) VALUES (?, ?, ?)",
                        (rule_id, cond["field_key"], cond["value"])
                    )
                conn.commit()
                return rule_id
        except Exception as e:
            logger.error(f"Ошибка сохранения правила: {e}")
            return -1

    def delete_rule(self, rule_id: int) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM auto_rules WHERE id = ?", (rule_id,))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка удаления правила: {e}")
            return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE auto_rules SET enabled = ? WHERE id = ?",
                    (int(enabled), rule_id)
                )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка переключения правила: {e}")
            return False