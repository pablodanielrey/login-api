
import os
import datetime
import hashlib
import logging

from sqlalchemy import or_, and_

import oidc
from oidc.oidc import ClientCredentialsGrant

from .entities import UsuarioClave
from .HydraModel import HydraModel

class LoginModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 0)))
    OIDC_URL = os.environ['OIDC_URL']
    OIDC_ADMIN_URL = os.environ['OIDC_ADMIN_URL']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']

    hydra = HydraModel(OIDC_ADMIN_URL, verify)
    grant = ClientCredentialsGrant(OIDC_URL, client_id, client_secret, verify=verify)
    
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


    """ 
        -----------------
        El flujo de login 
        -----------------
    """

    @classmethod
    def init_login_flow(cls, challenge):
        lc = cls.hydra.obtener_login_challenge(challenge)
        r = {
            'redirect_to': None
        }
        if lc['skip']:
            r = cls.aceptar_login_challenge(challenge,lc)
        return r

    @classmethod
    def login(cls, session, usuario, clave, challenge):

        ahora = datetime.datetime.now()
        logging.info('FECHA ACTUAL')
        logging.info(ahora)

        q = session.query(UsuarioClave).filter(UsuarioClave.usuario == usuario, UsuarioClave.clave == clave, UsuarioClave.eliminada == None)
        q = q.filter(or_(UsuarioClave.expiracion == None, UsuarioClave.expiracion > ahora))
        c = q.one_or_none()
        if not c:
            r = cls.denegar_login_challenge(challenge, error='unknown_user', descripcion='Usuario o clave incorrectos')
        else:
            """
            #TODO: hace falta chequear el debe cambiarla para loguearlo y redirigirlo a usuarios.
            """            
            r = cls.aceptar_login_challenge(challenge, uid=c.usuario_id)
        return r

    @classmethod
    def aceptar_login_challenge(cls, challenge, lc=None, uid=None, recordar=True, timeout=3600):
        if not lc:
            lc = cls.hydra.obtener_login_challenge(challenge)
        data = {
            'subject': lc['subject'] if lc['skip'] else uid,
            'remember': False if lc['skip'] else recordar,
            'remember_for': timeout,
            'acr':''
        }
        return cls.hydra.aceptar_login_challenge(challenge, data)

    @classmethod
    def denegar_login_challenge(cls, challenge, error='', descripcion=''):
        data = {
            'error': error,
            'error_description': descripcion
        }
        return cls.hydra.denegar_login_challenge(challenge, data)


    """ 
        ---------------------
        El flujo de consent 
        ---------------------
    """

    @classmethod
    def init_consent_flow(cls, challenge):
        cc = cls.hydra.obtener_consent_challenge(challenge)
        r = {
            'redirect_to': None
        }
        if cc['skip']:
            r = cls.aceptar_consent_challenge(challenge,cc)
        else:
            """
                En nuestro caso siempre aceptamos los consent ya que son apps internas
                Para cumplir con la especificación habría que mostrar una pantalla con el consent de los scopes
            """
            r = cls.aceptar_consent_challenge(challenge,cc)
        return r

    @classmethod
    def aceptar_consent_challenge(cls, challenge, cc=None, recordar=True, timeout=3600):
        if not cc:
            cc = cls.hydra.obtener_consent_challenge(challenge)
        data = {
            'grant_scope': cc['requested_scope'],
            'remember': False if cc['skip'] else recordar,
            'remember_for': timeout,
            'session':{
                'access_token':{},
                'id_token':{}
            }
        }            
        return cls.hydra.aceptar_consent_challenge(challenge, data)


    """
        métodos utilitarios para la administración 
    """

    @classmethod
    def logout_hydra(cls, client_id, uid):
        c = cls.hydra.obtener_cliente(client_id)
        ''' https://www.ory.sh/docs/api/hydra/?version=latest '''
        url = c['client_uri']
        r = {
            'redirect_to': url
        }        
        cls.hydra.eliminar_sesion_login_usuario(uid)
        return r

    @classmethod
    def obtener_sesiones_usuario(cls, uid):
        return cls.hydra.obtener_consent_sesiones(uid)

    @classmethod
    def eliminar_sesiones_usuario(cls, uid):
        cls.hydra.eliminar_sesion_login_usuario(uid)
        cls.hydra.eliminar_sesiones_usuario(uid)
        
    @classmethod
    def eliminar_sesiones_usuario_cliente(cls, uid, cid):
        cls.hydra.eliminar_sesiones_cliente_usuario(cid, uid)

