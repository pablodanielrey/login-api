
import uuid
import random
import datetime

from users.model.UsersModel import UsersModel
from login_api.model.MailsModel import MailsModel

from .entities.CredentialsReset import CredentialsReset

class RecoverModel:

    MAX_RESETS = 5

    def __init__(self, recover_session, users_session, loginModel, mailsModel, internal_domains=[]):
        self.recover_session = recover_session
        self.users_session = users_session
        self.mailsModel = mailsModel
        self.loginModel = loginModel
        self.internal_domains = internal_domains

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
            r = self.mailsModel.enviar_correo('sistema@econo.unlp.edu.ar', m.email, 'Reseteo de Clave FCE', text)
            if r.ok:
                sent.append(m.email)
        return sent

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

        """
            chequeo la cantidad de intentos por usuario
        """
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        resets = self.recover_session.query(CredentialsReset).filter(CredentialsReset.user_id == uid, CredentialsReset.verified == None, CredentialsReset.created > yesterday).count()
        if resets > self.MAX_RESETS:
            raise Exception('Se llegó al límite de intentos por día')

        users = UsersModel.get_users(self.users_session, uids=[uid])
        user = users[0]

        mails = [m for m in user.mails if m.confirmed and not m.deleted]
        external = self._get_external_mails(mails)
        if len(external) <= 0:
            raise Exception('No tiene correos de contacto confirmados')

        if resets >= 2:
            """ si ya se generaron 2 resets para este día, entonces los recupero y uso esos. """
            resets = self.recover_session.query(CredentialsReset).filter(
                CredentialsReset.user_id == uid, 
                CredentialsReset.verified == None, 
                CredentialsReset.deleted == None).all()

            sent = [r.email for r in resets]

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
            CredentialsReset.verified == None, 
            CredentialsReset.deleted == None).one_or_none()

        if not cr:
            raise Exception('Código inválido')

        """
            Si verifico un código, verifico todos los que tenga pendientes así se invalidan
        """
        session = cr.id
        now = datetime.datetime.utcnow()
        codes = self.recover_session.query(CredentialsReset).filter(CredentialsReset.user_id == uid, CredentialsReset.verified == None, CredentialsReset.deleted == None).all()
        for c in codes:
            c.verified = now
            c.updated = now

        return session

    
    def change_credentials(self, crid, credentials):

        cr = self.recover_session.query(CredentialsReset).filter(CredentialsReset.id == crid).one_or_none()
        if not cr:
            raise Exception('Código de seguridad inválido')
    
        if not cr.verified or cr.deleted:
            raise Exception('Código de seguridad inválido')

        cr.deleted = datetime.datetime.utcnow()

        """ ejecuto el cambio de credenciales """

        uid = cr.user_id
        username = cr.username

        cid = self.loginModel.change_credentials(self.recover_session, uid, username, credentials)

        return cid
