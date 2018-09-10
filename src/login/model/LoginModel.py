
import os
import datetime
import hashlib

import oidc
from oidc.oidc import ClientCredentialsGrant

from .entities import UsuarioClave, Sesion

class LoginModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 0)))
    USERS_API_URL = os.environ['USERS_API_URL']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']

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
    def login(cls, session, usuario, clave):
        c = session.query(UsuarioClave).filter(UsuarioClave.usuario == usuario, UsuarioClave.clave == clave).one()
        token = cls._crear_sesion(session, c.id)
        return token

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
