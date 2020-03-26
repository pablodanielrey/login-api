
import os
import pulsar

PULSAR_URL = os.environ.get('PULSAR_URL', 'pulsar://localhost:6650')
PULSAR_TOPIC = os.environ.get('PULSAR_TOPIC', 'google')
PULSAR_SUBSCRIPTION = os.environ.get('PULSAR_SUBSCRIPTION', 'google')


class EventsModel:

    def __init__(self):
        self.client = pulsar.Client(PULSAR_URL)
        self.producer = self.client.create_producer(PULSAR_TOPIC)

    def __del__(self):
        self.producer.close()
        self.client.close()

    def send(self, msg):
        self.producer.send(msg.encode('utf-8'))
