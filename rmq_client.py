# rmq_client.py
import pika
import logging
import json
from typing import Callable, Optional

logger = logging.getLogger(__name__)

class RMQClient:
    def __init__(self, host='localhost', port=5672, exchange='uedr', queue='incidents'):
        self.host = host
        self.port = port
        self.exchange = exchange
        self.queue = queue
        self._connection: Optional[pika.BlockingConnection] = None
        self._channel: Optional[pika.BlockingChannel] = None
        self._ensure_connection()

    def _ensure_connection(self):
        if self._connection and self._connection.is_open:
            return
        try:
            self._connection = pika.BlockingConnection(pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                heartbeat=600,
                blocked_connection_timeout=300
            ))
            self._channel = self._connection.channel()
            self._channel.exchange_declare(exchange=self.exchange, exchange_type='direct', durable=True)
            self._channel.queue_declare(queue=self.queue, durable=True)
            self._channel.queue_bind(exchange=self.exchange, queue=self.queue, routing_key='incident')
            logger.info(f"RMQ: подключён к {self.host}:{self.port}, очередь '{self.queue}' готова")
        except Exception as e:
            logger.error(f"RMQ: ошибка подключения: {e}")
            raise

    def publish_incident(self, payload: dict, source_ip: str):
        self._ensure_connection()
        message = {
            "payload": payload,
            "source_ip": source_ip,
            "timestamp": payload.get("timestamp") or None
        }
        try:
            self._channel.basic_publish(
                exchange=self.exchange,
                routing_key='incident',
                body=json.dumps(message, ensure_ascii=False),
                properties=pika.BasicProperties(delivery_mode=2)  # persistent
            )
            logger.debug("RMQ: инцидент отправлен в очередь")
        except Exception as e:
            logger.error(f"RMQ: ошибка публикации: {e}")
            raise

    def consume_incidents(self, callback: Callable[[dict, str, float], None]):
        def on_message(channel, method, properties, body):
            try:
                data = json.loads(body)
                payload = data["payload"]
                source_ip = data["source_ip"]
                timestamp = data.get("timestamp") or None
                callback(payload, source_ip, timestamp)
                channel.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as e:
                logger.exception("RMQ: ошибка обработки сообщения")
                channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        self._ensure_connection()
        self._channel.basic_qos(prefetch_count=1)
        self._channel.basic_consume(queue=self.queue, on_message_callback=on_message)
        logger.info("RMQ: запущено ожидание сообщений...")
        try:
            self._channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("RMQ: потребление прервано")
            self._channel.stop_consuming()
        finally:
            if self._connection and self._connection.is_open:
                self._connection.close()