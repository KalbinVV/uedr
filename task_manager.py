# task_manager.py
import threading
import time
import logging

logger = logging.getLogger(__name__)

class TaskManager:
    def __init__(self, max_tasks=100):
        self.tasks = {}  # { task_id: { ... } }
        self.lock = threading.Lock()
        self.max_tasks = max_tasks

    def submit_task(self, task_id: str, target_func, *args, **kwargs):
        def wrapper():
            try:
                result = target_func(*args, **kwargs)
                status = "completed"
                error = None
            except Exception as e:
                logger.exception("Исключение в задаче")
                result = None
                status = "failed"
                error = str(e)
            with self.lock:
                if task_id in self.tasks:
                    self.tasks[task_id].update({
                        "status": status,
                        "result": result,
                        "error": error,
                        "finished_at": time.time()
                    })
                self._cleanup()

        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
        with self.lock:
            self.tasks[task_id] = {
                "task_id": task_id,  # ← сохраняем ID внутри задачи
                "status": "running",
                "started_at": time.time(),
                "finished_at": None,
                "result": None,
                "error": None
            }

    def get_task(self, task_id: str):
        with self.lock:
            return self.tasks.get(task_id)

    def get_all_tasks_with_ids(self):
        with self.lock:
            # Возвращаем список задач, каждая содержит свой task_id
            task_list = list(self.tasks.values())
            return sorted(task_list, key=lambda t: t.get("started_at", 0), reverse=True)

    def _cleanup(self):
        if len(self.tasks) > self.max_tasks:
            sorted_items = sorted(self.tasks.items(), key=lambda x: x[1].get("started_at", 0))
            keys_to_remove = [key for key, _ in sorted_items[:len(sorted_items) - self.max_tasks]]
            for key in keys_to_remove:
                self.tasks.pop(key, None)