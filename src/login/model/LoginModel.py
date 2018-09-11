
import os
import datetime
import hashlib

import oidc
from oidc.oidc import ClientCredentialsGrant

from .entities import UsuarioClave, Sesion
from .HydraModel import HydraModel

class LoginModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 0)))
    USERS_API_URL = os.environ['USERS_API_URL']
    OIDC_HOST = os.environ['OIDC_HOST']
    OIDC_ADMIN_HOST = os.environ['OIDC_ADMIN_HOST']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']

    hydra = HydraModel(OIDC_ADMIN_HOST, verify)
    grant = ClientCredentialsGrant(client_id, client_secret, verify=verify)

    @classmethod
    def _obtener_token(cls):
        token = cls.grant.get_token(cls.grant.access_token())
        if not token:
            raise Exception('error obteniendo token de acceso')
        return token

    @classmethod
    def _obtener_token_sesion(cls, sid):
        d = str(datetime.datetime.now())
        h = '{}-{}'.format(sid,d).encode('utf-8')
        return hashlib.sha1(h).hexdigest()

    @classmethod
    def _crear_sesion(cls, session, ucid):
        ahora = datetime.datetime.now()
        l = session.query(Sesion).filter(Sesion.usuario_clave_id == ucid, Sesion.expirado < ahora).one_or_none()
        if not l:
            l = Sesion()
            l.token = cls._obtener_token_sesion(l.id)
            l.usuario_clave_id = ucid
            session.add(l)
        return l.token

    @classmethod
    def obtener_access_token(cls, session, sesion_token, consent_id):
        ahora = datetime.datetime.now()
        if session.query(Sesion).filter(Sesion.token == sesion_token, Sesion.expirado < ahora).count() < 1:
            raise Exception('error de sesion')




    """ pasos del proceso de login con hydra """

    @classmethod
    def obtener_login_challenge(cls, challenge):
        return cls.hydra.obtener_login_challenge(challenge)

    @classmethod
    def login(cls, session, usuario, clave):
        c = session.query(UsuarioClave).filter(UsuarioClave.usuario == usuario, UsuarioClave.clave == clave).one()
        return c.usuario_id

    @classmethod
    def aceptar_login_challenge(cls, challenge, uid=None):
        lc = cls.hydra.obtener_login_challenge(challenge)
        if uid:
            lc['subject'] = uid
        return cls.hydra.aceptar_login_challenge(challenge, lc)

    @classmethod
    def obtener_consent_challenge(cls, challenge):
        return cls.hydra.obtener_consent_challenge(challenge)

    @classmethod
    def aceptar_consent_challenge(cls, challenge):
        c = cls.hydra.obtener_consent_challenge(challenge)
        return cls.hydra.aceptar_consent_challenge(challenge, c)
