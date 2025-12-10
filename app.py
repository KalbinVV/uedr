# app.py
import json
import os
import logging
import sys
import uuid
import atexit
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime

# Настройка логгера ПОСЛЕ Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)


def setup_logging():
    LOG_FILE = "uedr_debug.log"
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)-8s %(name)-12s: %(message)s')
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.DEBUG)
    app.logger.propagate = False
    app.logger.info("=== ЛОГГИРОВАНИЕ НАСТРОЕНО ===")


setup_logging()

from database import UserDatabase
from auth import AuthManager
from salt_manager import SaltManager
from salt_script_manager import SaltScriptManager
from task_manager import TaskManager
from syslog_server import SyslogUDPServer
from incident_config import IncidentConfig
from auto_responder import AutoResponder

db = UserDatabase("users.db")
auth = AuthManager(db)
salt_mgr = SaltManager()
script_mgr = SaltScriptManager()
task_mgr = TaskManager()
incident_config = IncidentConfig(db)
auto_responder = AutoResponder(db, task_mgr, salt_mgr, script_mgr)
syslog_server = SyslogUDPServer(db, incident_config, salt_mgr, auto_responder)
syslog_server.start()
atexit.register(lambda: syslog_server.stop())

if not db.get_user("admin"):
    auth.register_user("admin", "admin")


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if auth.authenticate(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Неверные данные.", "error")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Миньоны
    minions_summary = []
    salt_error = None
    if salt_mgr.is_available():
        try:
            minions = salt_mgr.get_all_minions_info()
            minions_summary = minions
        except Exception as e:
            salt_error = f"Ошибка Salt: {str(e)}"
    else:
        salt_error = "Salt Master недоступен"

    # Последние инциденты
    last_incidents = db.get_all_incidents(limit=5)
    incident_fields = db.get_incident_fields()

    # Последние задачи
    last_tasks = task_mgr.get_all_tasks_with_ids()[:5]

    # Данные для графика (инциденты за последние 24 часа)
    import time
    now = time.time()
    last_24h = now - 24 * 3600
    all_incidents = db.get_all_incidents(limit=1000)
    # Группировка по часам
    hourly = [0] * 24
    for inc in all_incidents:
        ts = inc["timestamp"]
        if ts >= last_24h:
            hour = int((now - ts) / 3600)
            if 0 <= hour < 24:
                hourly[23 - hour] += 1  # от старых к новым

    return render_template(
        'dashboard.html',
        username=session['username'],
        minions=minions_summary,
        salt_error=salt_error,
        last_incidents=last_incidents,
        incident_fields=incident_fields,
        last_tasks=last_tasks,
        chart_data=hourly
    )


@app.route('/api/dashboard-data')
@login_required
def dashboard_data_api():
    """Возвращает JSON с данными для автообновления дашборда."""
    try:
        # Инциденты
        last_incidents = db.get_all_incidents(limit=5)
        incident_fields = db.get_incident_fields()

        # Задачи
        last_tasks = task_mgr.get_all_tasks_with_ids()[:5]

        # График: инциденты за 24 часа
        import time
        now = time.time()
        last_24h = now - 24 * 3600
        all_incidents = db.get_all_incidents(limit=1000)
        hourly = [0] * 24
        for inc in all_incidents:
            ts = inc["timestamp"]
            if ts >= last_24h:
                hour = int((now - ts) / 3600)
                if 0 <= hour < 24:
                    hourly[23 - hour] += 1

        return jsonify({
            "last_incidents": last_incidents,
            "incident_fields": incident_fields,
            "last_tasks": last_tasks,
            "chart_data": hourly,
            "timestamp": time.time()
        })
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.exception("Ошибка в dashboard_data_api")
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard-incidents-html')
@login_required
def dashboard_incidents_html():
    last_incidents = db.get_all_incidents(limit=5)
    incident_fields = db.get_incident_fields()
    return render_template('dashboard_incidents_table.html', last_incidents=last_incidents, incident_fields=incident_fields)

@app.route('/api/dashboard-tasks-html')
@login_required
def dashboard_tasks_html():
    last_tasks = task_mgr.get_all_tasks_with_ids()[:5]
    return render_template('dashboard_tasks_table.html', last_tasks=last_tasks)


@app.route('/minion/<minion_id>')
@login_required
def minion_detail(minion_id):
    details = salt_mgr.get_minion_details(minion_id)
    if not details:
        flash("Не удалось получить данные миньона.", "error")
        return redirect(url_for('dashboard'))
    return render_template('minion_detail.html', username=session['username'], minion=details)


@app.route('/scripts')
@login_required
def scripts():
    script_name = request.args.get('script')
    current_content = ""

    if script_name:
        current_content = script_mgr.get_script_content(script_name)
    script_names = script_mgr.list_scripts()
    minions = salt_mgr.get_all_minions_info() if salt_mgr.is_available() else []

    return render_template(
        'scripts.html',
        username=session['username'],
        scripts=script_names,
        minions=minions,
        current_script=script_name,
        current_content=current_content
    )


@app.route('/script/edit/<name>', methods=['GET'])
@login_required
def edit_script(name):
    content = script_mgr.get_script_content(name) if name else ""
    return jsonify({
        "name": name,
        "content": content
    })


@app.route('/api/script/save', methods=['POST'])
@login_required
def save_script_api():
    """API для сохранения сценария через AJAX."""
    script_name = request.form.get('name', '').strip()
    content = request.form.get('content', '')
    if not script_name:
        return jsonify({"success": False, "error": "Имя обязательно."}), 400
    if not script_mgr.save_script(script_name, content):
        return jsonify({"success": False, "error": "Недопустимое имя."}), 400
    return jsonify({
        "success": True,
        "message": f"Сценарий '{script_name}' сохранён.",
        "script_name": script_name
    })


@app.route('/script/delete/<name>', methods=['POST'])
@login_required
def delete_script(name):
    if script_mgr.delete_script(name):
        flash(f"Сценарий '{name}' удалён.", "success")
    else:
        flash("Ошибка удаления.", "error")
    return redirect(url_for('scripts'))


@app.route('/script/apply', methods=['POST'])
@login_required
def apply_script():
    minion_id = request.form.get('minion_id')
    script_name = request.form.get('script_name')
    if not minion_id or not script_name:
        flash("Выберите миньон и сценарий.", "error")
        return redirect(url_for('scripts'))
    task_id = str(uuid.uuid4())
    task_mgr.submit_task(task_id, _run_salt_state, minion_id, script_name)
    flash(f"Задача запущена. ID: {task_id[:8]}...", "success")
    return redirect(url_for('tasks'))


def _run_salt_state(minion_id: str, state_name: str):
    logger = logging.getLogger(__name__)
    logger.info(f"[Фон] Запуск state '{state_name}' на '{minion_id}'")
    try:
        # Для ручного запуска — контекст пустой
        temp_path = script_mgr.render_script(state_name, {})
        raw_result = salt_mgr.apply_rendered_state(minion_id, temp_path)
        return {
            "minion": minion_id,
            "state": state_name,
            "details": raw_result
        }
    except Exception as e:
        logger.exception("Ошибка в фоновой задаче")
        return {
            "minion": minion_id,
            "state": state_name,
            "error": str(e)
        }


@app.route('/tasks')
@login_required
def tasks():
    task_list = task_mgr.get_all_tasks_with_ids()
    return render_template('tasks.html', username=session['username'], tasks=task_list)


@app.route('/task/<task_id>')
@login_required
def task_detail(task_id):
    task = task_mgr.get_task(task_id)
    if not task:
        flash("Задача не найдена.", "error")
        return redirect(url_for('tasks'))
    return render_template('task_detail.html', username=session['username'], task=task, task_id=task_id)


@app.route('/incidents')
@login_required
def incidents():
    incident_list = db.get_all_incidents(limit=200)
    fields = db.get_incident_fields()
    return render_template('incidents.html', username=session['username'], incidents=incident_list, fields=fields)


@app.route('/incident-config', methods=['GET', 'POST'])
@login_required
def incident_config_view():
    if request.method == 'POST':
        src_ip_path = request.form.get('src_ip_path', '').strip()
        src_hostname_path = request.form.get('src_hostname_path', '').strip()

        # Валидация: хотя бы одно поле должно быть заполнено
        if not src_ip_path and not src_hostname_path:
            flash("Укажите хотя бы одно поле: IP-адрес или hostname источника.", "error")
            return render_template('incident_config.html',
                                   username=session['username'],
                                   src_ip_path=src_ip_path,
                                   src_hostname_path=src_hostname_path,
                                   custom_fields=[])

        # Подготавливаем список полей
        fields = []

        # Обязательные поля (с фиксированными ключами)
        if src_ip_path:
            fields.append({
                "display_name": "IP источника",
                "field_key": "src_ip",
                "json_path": src_ip_path
            })
        if src_hostname_path:
            fields.append({
                "display_name": "Hostname источника",
                "field_key": "src_hostname",
                "json_path": src_hostname_path
            })

        # Дополнительные поля
        i = 0
        while True:
            display_name = request.form.get(f'display_name_{i}')
            field_key = request.form.get(f'field_key_{i}')
            json_path = request.form.get(f'json_path_{i}')
            if not display_name and not field_key and not json_path:
                break
            if display_name and field_key and json_path:
                fields.append({
                    "display_name": display_name.strip(),
                    "field_key": field_key.strip(),
                    "json_path": json_path.strip()
                })
            i += 1

        if incident_config.save_fields(fields):
            flash("Конфигурация сохранена.", "success")
        else:
            flash("Ошибка сохранения конфигурации.", "error")
        return redirect(url_for('incident_config_view'))

    # GET: загружаем текущую конфигурацию
    config = incident_config.get_all_fields()
    src_ip_path = None
    src_hostname_path = None
    custom_fields = []

    for field in config:
        if field["field_key"] == "src_ip":
            src_ip_path = field["json_path"]
        elif field["field_key"] == "src_hostname":
            src_hostname_path = field["json_path"]
        else:
            custom_fields.append(field)

    return render_template('incident_config.html',
                           username=session['username'],
                           src_ip_path=src_ip_path,
                           src_hostname_path=src_hostname_path,
                           custom_fields=custom_fields)


@app.route('/incident-config/export')
@login_required
def export_incident_config():
    """Экспорт конфигурации в JSON-файл."""
    config = incident_config.get_all_fields()
    return jsonify(config), 200, {
        'Content-Disposition': 'attachment; filename=uedr_incident_config.json',
        'Content-Type': 'application/json; charset=utf-8'
    }


@app.route('/incident-config/import', methods=['POST'])
@login_required
def import_incident_config():
    """Импорт конфигурации из загруженного JSON-файла."""
    if 'config_file' not in request.files:
        flash("Файл не выбран.", "error")
        return redirect(url_for('incident_config_view'))

    file = request.files['config_file']
    if not file.filename.endswith('.json'):
        flash("Разрешены только .json файлы.", "error")
        return redirect(url_for('incident_config_view'))

    try:
        content = file.read().decode('utf-8')
        config = json.loads(content)
    except Exception as e:
        flash(f"Ошибка чтения файла: {e}", "error")
        return redirect(url_for('incident_config_view'))

    # Валидация структуры
    if not isinstance(config, list):
        flash("Неверный формат: ожидается список полей.", "error")
        return redirect(url_for('incident_config_view'))

    for field in config:
        if not all(k in field for k in ("display_name", "field_key", "json_path")):
            flash("Неверный формат поля: должно содержать display_name, field_key, json_path.", "error")
            return redirect(url_for('incident_config_view'))

    # Сохраняем
    if incident_config.save_fields(config):
        flash("Конфигурация успешно импортирована.", "success")
    else:
        flash("Ошибка сохранения конфигурации.", "error")

    return redirect(url_for('incident_config_view'))


@app.route('/rules')
@login_required
def rules():
    rules_list = db.get_all_rules()
    scripts = script_mgr.list_scripts()
    return render_template('rules.html', username=session['username'], rules=rules_list, scripts=scripts)


@app.route('/api/rule/<int:rule_id>')
@login_required
def api_get_rule(rule_id):
    rules = db.get_all_rules()
    rule = next((r for r in rules if r["id"] == rule_id), None)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(rule)


@app.route('/rule/edit', methods=['GET', 'POST'])
@app.route('/rule/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id=None):
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        logic = request.form.get('logic', 'AND')
        script_name = request.form.get('script_name', '').strip()
        enabled = 'enabled' in request.form

        if not name or not script_name:
            flash("Имя правила и сценарий обязательны.", "error")
            scripts = script_mgr.list_scripts()
            return render_template('edit_rule.html', username=session['username'], scripts=scripts)

        # Собираем условия
        conditions = []
        i = 0
        while True:
            field_key = request.form.get(f'cond_field_{i}')
            value = request.form.get(f'cond_value_{i}')
            if field_key is None and value is None:
                break
            if field_key and value:
                conditions.append({"field_key": field_key.strip(), "value": value.strip()})
            i += 1

        if not conditions:
            flash("Добавьте хотя бы одно условие.", "error")
            scripts = script_mgr.list_scripts()
            return render_template('edit_rule.html', username=session['username'], scripts=scripts)

        if rule_id:
            db.delete_rule(rule_id)
        db.save_rule(name, logic, script_name, conditions, enabled)
        flash("Правило сохранено.", "success")
        return redirect(url_for('rules'))

    # GET
    scripts = script_mgr.list_scripts()
    rule = None
    if rule_id:
        rules = db.get_all_rules()
        rule = next((r for r in rules if r["id"] == rule_id), None)
    return render_template('edit_rule.html', username=session['username'], scripts=scripts, rule=rule)

@app.route('/rule/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    if db.delete_rule(rule_id):
        flash("Правило удалено.", "success")
    else:
        flash("Ошибка удаления правила.", "error")
    return redirect(url_for('rules'))

@app.route('/rule/toggle/<int:rule_id>', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    rule = next((r for r in db.get_all_rules() if r["id"] == rule_id), None)
    if rule:
        new_state = not rule["enabled"]
        if db.toggle_rule(rule_id, new_state):
            flash(f"Правило {'включено' if new_state else 'выключено'}.", "success")
        else:
            flash("Ошибка переключения правила.", "error")
    else:
        flash("Правило не найдено.", "error")
    return redirect(url_for('rules'))


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Фильтр для форматирования временных меток."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value).strftime(format)
    return value

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)