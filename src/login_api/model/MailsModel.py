
import os
import base64
import requests
from jinja2 import Environment, PackageLoader, FileSystemLoader

class MailsModel:

    #EMAILS_API_URL = os.environ['EMAILS_API_URL']

    def __init__(self, emails_api):
        self.emails_api = emails_api
        self.env = Environment(loader=PackageLoader('login_api.model.templates','.'))

    def obtener_template(self, template):
        templ = self.env.get_template(template)
        return templ

    def enviar_correo(self, de, para, asunto, cuerpo):
        ''' https://developers.google.com/gmail/api/guides/sending '''
        bcuerpo = base64.urlsafe_b64encode(cuerpo.encode('utf-8')).decode()
        r = requests.post(f'{self.emails_api}/correos/', json={'sistema':'login', 'de':de, 'para':para, 'asunto':asunto, 'cuerpo':bcuerpo})
        return r
