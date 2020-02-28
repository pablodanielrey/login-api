
import os
import datetime
import hashlib
import logging
from dateutil.parser import parse

from sqlalchemy import or_, and_

import oidc
from oidc.oidc import ClientCredentialsGrant

from model_utils.API import API

from .entities import UsuarioClave
from .HydraModel import HydraModel

CLIENT_ID = os.environ['OIDC_CLIENT_ID']
CLIENT_SECRET = os.environ['OIDC_CLIENT_SECRET']
OIDC_URL = os.environ['OIDC_URL']
OIDC_ADMIN_URL = os.environ['OIDC_ADMIN_URL']
VERIFY_SSL = bool(int(os.environ.get('VERIFY_SSL', 0)))
USERS_API_URL = os.environ.get('USERS_API_URL')

class LoginModel:

    verify = VERIFY_SSL
    OIDC_URL = OIDC_URL
    OIDC_ADMIN_URL = OIDC_ADMIN_URL
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET

    api = API(url=OIDC_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify_ssl=VERIFY_SSL)
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

    """
        https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
    """
    @classmethod
    def aceptar_consent_challenge(cls, challenge, cc=None, recordar=True, timeout=3600):
        if not cc:
            cc = cls.hydra.obtener_consent_challenge(challenge)


        """
            /////////////////
            TODO: cambiar este hack horrible a la api de usuarios!!!
            lo mejor a hacer es usar eventsourcing.
        """
        uid = cc['subject']
        tk = cls.api._get_token()

        def _get_user_uuid(api, uuid, token=None):
            query = '{}/usuarios/{}'.format(USERS_API_URL, uuid)
            r = api.get(query, token=token)
            if not r.ok:
                return None
            usr = r.json()
            if len(usr) > 0:
                return usr[0]
            return None

        def _get_primary_email(usr):
            if 'mails' not in usr:
                return None
            mails = sorted([m for m in usr['mails'] if m['confirmado'] and not m['eliminado']], key=lambda m: m['email'])
            if len(mails) > 0:
                return mails[0]
            return None

        usr = _get_user_uuid(cls.api, uid, tk)
        if not usr:
            raise Exception('error obteniendo datos de usuario')

        """
            //////////////////////////
        """

        atk = {}
        if 'profile' in cc['requested_scope']:
            atk['name'] = usr['nombre']
            atk['family_name'] = usr['apellido']
            atk['given_name'] = usr['nombre']
            atk['middle_name'] = usr['nombre'].split(' ')[1] if len(usr['nombre'].split(' ')) > 1 else ''
            atk['nickname'] = ''
            atk['preferred_username'] = usr['dni']
            atk['profile'] = ''
            atk['picture'] = ''
            atk['website'] = ''
            atk['gender'] = usr['genero']
            atk['birthdate'] = usr['nacimiento']
            atk['zoneinfo'] = 'America/Argentina/Buenos_Aires'
            atk['locale'] = 'es-ES'

            updated_at = None
            try:
                updated_at = parse(usr['actualizado']).timestamp()
            except Exception as ex:
                try:
                    updated_at = parse(usr['creado']).timestamp()
                except Exception as exx:
                    pass
            atk['updated_at'] = updated_at

        if 'email' in cc['requested_scope']:
            if 'mails' in usr: 
                em = _get_primary_email(usr)
                if em:
                    atk['email'] = em['email']
                    atk['email_verified'] = True if em['confirmado'] else False

        if 'address' in cc['requested_scope']:
            atk['address'] = {
                'street_address':usr['direccion'],
                'locality':usr['ciudad'],
                'country':usr['pais']
            }

        """
        if 'phone' in cc['requested_scope']:
            atk['phone_number'] = ''
            atk['phone_number_verified'] = ''
        """

        data = {
            'grant_scope': cc['requested_scope'],
            'remember': False if cc['skip'] else recordar,
            'remember_for': timeout,
            'session':{
                'access_token':atk,
                'id_token':atk
            }
        }            
        return cls.hydra.aceptar_consent_challenge(challenge, data)


    """
        métodos utilitarios para la administración 
    """

    @classmethod
    def logout_hydra(cls, client_id, uid):
        logging.debug('deslogueando a  {} en {}'.format(uid, client_id))
        c = cls.hydra.obtener_cliente(client_id)
        logging.debug(c)
        ''' https://www.ory.sh/docs/api/hydra/?version=latest '''
        url = c['client_uri']
        r = {
            'redirect_to': url
        }        
        cls.hydra.eliminar_sesion_login_usuario(uid)
        logging.debug(r)
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

