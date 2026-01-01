import salt.client
import logging
import os

logger = logging.getLogger(__name__)


class SaltManager:
    def __init__(self):
        try:
            self.local = salt.client.LocalClient()
        except Exception as e:
            logger.error(f"Salt не инициализирован: {e}")
            self.local = None

    def is_available(self):
        return self.local is not None

    def list_minions(self):
        if not self.is_available():
            return []
        try:
            result = self.local.cmd('*', 'test.ping', timeout=10)
            return [mid for mid, status in result.items() if status is True]
        except Exception as e:
            logger.error(f"Ошибка списка миньонов: {e}")
            return []

    def get_minion_grains(self, minion_id: str):
        if not self.is_available():
            return {}
        try:
            result = self.local.cmd(minion_id, 'grains.items', timeout=10)
            grains = result.get(minion_id, {})
            if not isinstance(grains, dict):
                logger.warning(f"Миньон {minion_id}: grains вернул не словарь: {grains}")
                return {}
            return grains
        except Exception as e:
            logger.error(f"Ошибка grains {minion_id}: {e}")
            return {}

    def get_minion_details(self, minion_id: str):
        if not self.is_available():
            return None
        try:
            ping = self.local.cmd(minion_id, 'test.ping', timeout=5)
            is_online = ping.get(minion_id, False) is True
            if not is_online:
                return {"id": minion_id, "is_online": False}

            grains = self.local.cmd(minion_id, 'grains.items', timeout=10).get(minion_id, {})
            if not isinstance(grains, dict):
                grains = {}

            cpu_info = self.local.cmd(minion_id, 'status.cpuinfo', timeout=10).get(minion_id, {})
            mem_info = self.local.cmd(minion_id, 'status.meminfo', timeout=10).get(minion_id, {})
            disk_usage = self.local.cmd(minion_id, 'disk.usage', timeout=10).get(minion_id, {})
            interfaces = self.local.cmd(minion_id, 'network.interfaces', timeout=10).get(minion_id, {})

            try:
                top = self.local.cmd(minion_id, 'ps.top', timeout=10).get(minion_id, [])
                top_10 = top[:10] if isinstance(top, list) else []
            except:
                top_10 = []

            ipv4_raw = grains.get('ipv4', [])
            if not isinstance(ipv4_raw, list):
                ipv4_raw = []

            return {
                "id": minion_id,
                "is_online": True,
                "grains": grains,
                "ipv4_all": ipv4_raw,
                "cpu_info": cpu_info,
                "mem_info": mem_info,
                "disk_usage": disk_usage,
                "interfaces": interfaces,
                "top_processes": top_10
            }
        except Exception as e:
            logger.exception(f"Ошибка получения деталей миньона {minion_id}")
            return {"id": minion_id, "is_online": False, "error": str(e)}

    def get_all_minions_info(self):
        if not self.is_available():
            return []
        try:
            pings = self.local.cmd('*', 'test.ping', timeout=5)
            online_minions = {mid for mid, status in pings.items() if status is True}
            minions_summary = []
            for mid in online_minions:
                grains = self.get_minion_grains(mid)
                os_name = grains.get('os', 'N/A')
                os_version = grains.get('osrelease', 'N/A')
                kernel = grains.get('kernelrelease', 'N/A')

                ip4 = grains.get('ipv4', [])
                if not isinstance(ip4, list):
                    ip4 = []

                ip_list = [str(ip) for ip in ip4 if ip and ip != '127.0.0.1' and ':' not in ip]
                minions_summary.append({
                    'id': mid,
                    'os': os_name,
                    'os_version': os_version,
                    'kernel': kernel,
                    'ip': ip_list,  # ✅ Список
                    'is_online': True
                })
            return minions_summary
        except Exception as e:
            logger.exception("Ошибка в get_all_minions_info")
            return []

    def apply_state(self, minion_id: str, state_name: str):
        if not self.is_available():
            return {"error": "Salt недоступен"}
        try:
            result = self.local.cmd(
                tgt=minion_id,
                fun='state.apply',
                arg=[state_name],
                timeout=60
            )
            return result.get(minion_id, {"error": f"Миньон {minion_id} не ответил"})
        except Exception as e:
            logger.exception("Ошибка apply_state")
            return {"error": str(e)}

    def apply_rendered_state(self, minion_id: str, script_path: str):
        if not self.is_available():
            return {"error": "Salt недоступен"}
        try:
            if script_path.startswith("/srv/salt/"):
                rel_path = os.path.relpath(script_path, "/srv/salt")
                state_name = rel_path.replace("/", ".").rstrip(".sls")
            else:
                tmp_salt_dir = "/srv/salt/uedr_tmp"
                os.makedirs(tmp_salt_dir, exist_ok=True)
                script_name = os.path.basename(script_path)
                target_path = os.path.join(tmp_salt_dir, script_name)
                with open(script_path, 'r') as src, open(target_path, 'w') as dst:
                    dst.write(src.read())
                state_name = f"uedr_tmp.{script_name[:-4]}"

            result = self.local.cmd(
                tgt=minion_id,
                fun='state.apply',
                arg=[state_name],
                timeout=60
            )
            return result.get(minion_id, {"error": f"Миньон {minion_id} не ответил"})
        except Exception as e:
            logger.exception("Ошибка apply_rendered_state")
            return {"error": str(e)}