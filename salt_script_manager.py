import os
import logging
import re
import tempfile

logger = logging.getLogger(__name__)

SALT_ENV_DIR = "/srv/salt"


class SaltScriptManager:
    def __init__(self):
        self.scripts_dir = SALT_ENV_DIR
        os.makedirs(self.scripts_dir, exist_ok=True)

    def list_scripts(self):
        try:
            return sorted([f[:-4] for f in os.listdir(self.scripts_dir) if f.endswith('.sls')])
        except Exception as e:
            logger.error(f"Ошибка списка: {e}")
            return []

    def save_script(self, name: str, content: str) -> bool:
        if not self._is_valid_name(name):
            return False
        path = os.path.join(self.scripts_dir, f"{name}.sls")
        try:
            with open(path, 'w') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Ошибка записи: {e}")
            return False

    def get_script_content(self, name: str) -> str:
        if not self._is_valid_name(name):
            return ""
        path = os.path.join(self.scripts_dir, f"{name}.sls")
        if not os.path.exists(path):
            return ""
        try:
            with open(path) as f:
                return f.read()
        except Exception as e:
            logger.error(f"Ошибка чтения: {e}")
            return ""

    def delete_script(self, name: str) -> bool:
        if not self._is_valid_name(name):
            return False
        path = os.path.join(self.scripts_dir, f"{name}.sls")
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
            return False
        except Exception as e:
            logger.error(f"Ошибка удаления: {e}")
            return False

    def _is_valid_name(self, name: str) -> bool:
        return re.match(r'^[a-zA-Z0-9_-]+$', name) is not None

    def render_script(self, script_name: str, context: dict) -> str:
        original_content = self.get_script_content(script_name)
        if not original_content:
            raise FileNotFoundError(f"Сценарий '{script_name}' не найден")

        if "{{" not in original_content:
            return os.path.join(self.scripts_dir, f"{script_name}.sls")

        def replace_match(match):
            key = match.group(1).strip()
            return str(context.get(key, match.group(0)))

        rendered_content = re.sub(r'\{\{([^}]+)\}\}', replace_match, original_content)

        temp_dir = "/tmp/uedr_scripts"
        os.makedirs(temp_dir, exist_ok=True)

        import hashlib
        hash_str = hashlib.md5(rendered_content.encode()).hexdigest()
        temp_path = os.path.join(temp_dir, f"{script_name}_{hash_str}.sls")
        with open(temp_path, 'w') as f:
            f.write(rendered_content)
        return temp_path