
import uuid
import random
import datetime
import re

from users.model.UsersModel import UsersModel
from login_api.model.MailsModel import MailsModel

from .EventsModel import EventsModel

from .entities.CredentialsReset import CredentialsReset

class RecoverModel:

    MAX_RESETS = 5
    REGEXP = re.compile(r"[a-zA-Z0-9_!\"$%&=!*@#;,:.+¿?\^\-]+")

    def __init__(self, recover_session, users_session, loginModel, mailsModel, internal_domains=[], reset_credentials_from='do-not-reply@domain.com', eventsModel=EventsModel()):
        self.recover_session = recover_session
        self.users_session = users_session
        self.mailsModel = mailsModel
        self.loginModel = loginModel
        self.internal_domains = internal_domains
        self.reset_credentials_from = reset_credentials_from
        self.events = eventsModel

    def _generate_code(self):
        return str(random.randint(1111,9999))

    def _ofuscate(self, email):
        parts = email.split('@')
        if len(parts[0]) > 3:
            parts[0] = parts[0][:3] + '*'*(len(parts[0])-3)
        if len(parts[1]) > 5:
            parts[1] = parts[1][:5] + '*'*(len(parts[1])-5) 
        return parts[0] + '@' + parts[1]

    def _send_code_to(self, user, code, mails):
        templ = self.mailsModel.obtener_template('code.tmpl')
        text = templ.render(user=user, code=code)
        sent = []
        for m in mails:
            r = self.mailsModel.enviar_correo(self.reset_credentials_from, m.email, 'Reseteo de Clave FCE', text)
            if r.ok:
                sent.append(m.email)
        return sent

    def _has_intenal_mail(self, mails):
        for m in mails:
            if m.email.split('@')[1] in self.internal_domains:
                return True
        return False

    def _get_external_mails(self, mails):
        return [m for m in mails if m.email.split('@')[1] not in self.internal_domains]
        
    def recover_for(self, id_number, device):
        """
            Genera el código necesario para verificar el correo de la persona y se lo envía a 
            todos los correos confirmados que tenga la persona.
        """
        uid = UsersModel.get_uid_person_number(self.users_session, id_number)
        if not uid:
            raise Exception('no existe el usuario')

        resets = self.recover_session.query(CredentialsReset).filter(
            CredentialsReset.user_id == uid, 
            CredentialsReset.verified == None, 
            CredentialsReset.deleted == None).count()

        if resets > self.MAX_RESETS:
            raise Exception('Se llegó al límite de intentos por día')

        users = UsersModel.get_users(self.users_session, uids=[uid])
        user = users[0]

        mails = [m for m in user.mails if m.confirmed and not m.deleted]
        external = self._get_external_mails(mails)
        if len(external) <= 0:
            raise Exception('No tiene correos de contacto confirmados')
 
        is_intenal = self._has_intenal_mail(mails)

        if resets > 0:
            reset = self.recover_session.query(CredentialsReset).filter(
                CredentialsReset.user_id == uid, 
                CredentialsReset.verified == None, 
                CredentialsReset.deleted == None).first()
            code = reset.code
        else:
            code = self._generate_code()

        sent = self._send_code_to(user, code, external)
        if len(sent) <= 0:
            raise Exception('No se pudo enviar el código')

        """
            Genero el registro de control de reseteos de credenciales
        """
        reset = CredentialsReset()
        reset.id = str(uuid.uuid4())
        reset.created = datetime.datetime.utcnow()
        reset.user_id = uid
        reset.username = id_number
        reset.code = code
        reset.verified = None
        reset.is_internal = is_intenal
        reset.email = sent[0]
        self.recover_session.add(reset)

        response = {
            'device': device,
            'user': id_number,
            'email': self._ofuscate(sent[0])
        }

        return response

    def verify_code(self, user_identity_number, code):

        uid = UsersModel.get_uid_person_number(self.users_session, user_identity_number)
        if not uid:
            raise Exception('Usuário inválido')

        cr = self.recover_session.query(CredentialsReset).filter(
            CredentialsReset.code == code, 
            CredentialsReset.user_id == uid, 
            CredentialsReset.deleted == None).one_or_none()

        if not cr:
            raise Exception('Código inválido')

        if cr.verified:
            raise Exception('Código ya verificado')

        """
            verifico este código y elimino todos los pendientes.
        """
        now = datetime.datetime.utcnow()
        session = cr.id
        cr.verified = now
        cr.updated = now

        codes = self.recover_session.query(CredentialsReset).filter(
                    CredentialsReset.id != cr.id,
                    CredentialsReset.user_id == uid, 
                    CredentialsReset.verified == None,
                    CredentialsReset.deleted == None).all()
        for c in codes:
            c.updated = now
            c.deleted = now

        return session

    def change_credentials(self, crid, credentials):

        """
            TODO: chequeo las credenciales por sintaxis válida!! usando regexp
        """
        m = self.REGEXP.match(credentials)
        if not m:
            raise Exception('Caracteres inválidos en las credenciales')
        
        cr = self.recover_session.query(CredentialsReset).filter(CredentialsReset.id == crid).one_or_none()
        if not cr:
            raise Exception('Código de seguridad inválido')
    
        if not cr.verified or cr.deleted:
            raise Exception('Código de seguridad inválido')

        cr.deleted = datetime.datetime.utcnow()
        uid = cr.user_id
        username = cr.username

        cid = self.loginModel.change_credentials(self.recover_session, uid, username, credentials)
        if cr.is_intenal:
            cr.email
            msg = f"{username};{credentials}"
            self.events.send(msg)

        return cid
