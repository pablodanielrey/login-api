
import os
import pulsar
from pulsar.schema import JsonSchema

from login.model.entities.Login import LoginEvent, LoginEventTypes

PULSAR_URL = os.environ.get('PULSAR_URL', 'pulsar://localhost:6650')
PULSAR_TOPIC = os.environ.get('PULSAR_TOPIC', 'google')
PULSAR_SUBSCRIPTION = os.environ.get('PULSAR_SUBSCRIPTION', 'google')


class EventsModel:

    def __init__(self):
        #self.client = pulsar.Client(PULSAR_URL)
        #self.producer = self.client.create_producer(topic=PULSAR_TOPIC, schema=JsonSchema(LoginEvent))
        pass

    def __del__(self):
        #self.producer.close()
        #self.client.close()
        pass

    def send(self, username, credentials):
        #msg = LoginEvent(type_=LoginEventTypes.CHANGE_CREDENTIALS.value, 
        #                 username=username, 
        #                 credentials=credentials)
        #self.producer.send(msg)
        pass
