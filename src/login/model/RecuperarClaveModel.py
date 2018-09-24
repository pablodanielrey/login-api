
import os
import datetime
import hashlib
import requests
import logging
import redis
import json
import uuid

import oidc
from oidc.oidc import ClientCredentialsGrant

from .entities import UsuarioClave, ResetClave
from .HydraModel import HydraModel

class RecuperarClaveModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 0)))
    INTERNAL_DOMAINS= os.environ['INTERNAL_DOMAINS'].split(',')
    OIDC_URL = os.environ['OIDC_URL']
    OIDC_ADMIN_URL = os.environ['OIDC_ADMIN_URL']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']
    REDIS_HOST = os.environ.get('REDIS_HOST','127.0.0.1')
    REDIS_PORT = int(os.environ.get('REDIS_PORT',6379))
    
    USERS_API_URL = os.environ['USERS_API_URL']

    grant = ClientCredentialsGrant(OIDC_URL, client_id, client_secret, verify=verify)
    redis = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    """
    ////////////// MANEJO DE CACHE ////////////////////////
    """

    @classmethod
    def _obtener_usuario_api(cls, url, token=None):
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }        
        r = requests.get(url, headers=headers, verify=cls.verify, allow_redirects=False)
        if not r.ok:
            logging.debug(r)
            raise Exception('error obteniendo usuario')
        usr = r.json()
        assert 'id' in usr
        cls._setear_usuario_cache(usr)
        return usr

    @classmethod
    def _setear_usuario_cache(cls, usr):
        uid = usr['id']
        for m in usr['mails']:
            mid = m['id']
            cls.redis.hmset('r_mail_{}'.format(mid), m)
            cls.redis.sadd('r_usuario_mails_{}'.format(uid), mid)
        cls.redis.hmset('r_usuario_uid_{}'.format(uid), usr)
        cls.redis.hset('r_usuario_dni_{}'.format(usr['dni'].lower().replace(' ','')), 'uid', uid)

    @classmethod
    def _format_mail_from_redis(cls, m):
        for k in m.keys():
            if m[k] == 'None':
                m[k] = None
        return m

    @classmethod
    def _obtener_correo_cache(cls, mid):
        key = 'r_mail_{}'.format(mid)
        if not cls.redis.hexists(key,'id'):
            return None
        mail = cls.redis.hgetall(key)
        fmail = cls._format_mail_from_redis(mail)
        return fmail

    @classmethod
    def _obtener_usuario_cache(cls, uid):
        assert uid is not None
        usr = cls.redis.hgetall('r_usuario_uid_{}'.format(uid))
        if len(usr.keys()) > 0:
            try:
                uid = usr['id']
                mailids = cls.redis.smembers('r_usuario_mails_{}'.format(uid))
                mails = [cls._obtener_correo_cache(mid) for mid in mailids if mid]
                usr['mails'] = [m for m in mails if m]
                return usr
            except Exception as e:
                logging.exception(e)
        return None



    @classmethod
    def _obtener_usuario_por_uid(cls, uid, token=None):
        usr = cls._obtener_usuario_cache(uid)
        if usr:
            return usr
        url = '{}/usuarios/{}'.format(cls.USERS_API_URL, uid)
        usr = cls._obtener_usuario_api(url, token)
        return usr

    @classmethod
    def _obtener_usuario_por_dni(cls, dni, token=None):
        key = 'r_usuario_dni_{}'.format(dni.lower().replace(' ',''))
        if cls.redis.hexists(key,'uid'):
            uid = cls.redis.hget(key,'uid')
            return cls._obtener_usuario_por_uid(uid, token)

        url = '{}/usuario_por_dni/{}'.format(cls.USERS_API_URL, dni)
        usr = cls._obtener_usuario_api(url, token)
        return usr

    @classmethod
    def _obtener_token(cls):
        token = cls.grant.get_token(cls.grant.access_token())
        if not token:
            raise Exception('error obteniendo token de acceso')
        return token


    """
        //////////////////////////
    """

    @classmethod
    def _obtener_correo_alternativo(cls, usr):
        correo = None
        correos_validos = [m for m in usr['mails'] if not m['eliminado'] and m['confirmado']]
        correo = [m for m in correos_validos if m['email'].split('@')[1] not in cls.INTERNAL_DOMAINS]
        if len(correo) <= 0:
            return None
        else:
            return correo[0]

    @classmethod
    def verificar_dni(cls, dni):
        usr = cls._obtener_usuario_por_dni(dni)
        c = cls._obtener_correo_alternativo(usr)
        if c:
            return {'tiene_correo':True, 'usuario':usr}
        else:
            return {'tiene_correo':False, 'usuario':usr}

    @classmethod
    def obtener_correo(cls, uid):
        usr = cls._obtener_usuario_por_uid(uid)
        correo = cls._obtener_correo_alternativo(usr)
        if not correo:
            raise Exception('No tiene correo alternativo')

        """ genero el ofuscamiento de la direccion """
        mail = correo['email']
        cs = mail.split('@')
        ayuda = None
        if len(cs[0]) <= 3:
            ayuda = mail
        else:
            l = int(len(cs[0]) / 2)
            ayuda = cs[0][:-l] + ('*' * l) + '@' + cs[1]

        r = {
            'correo': {
                'id': correo['id'],
                'ayuda': ayuda
            },
            'usuario': usr
        }
        return r

    @classmethod
    def _generar_codigo(cls):
        return str(uuid.uuid4())[:8]

    @classmethod
    def _enviar_codigo_template(cls, codigo, correo):
        pass

    @classmethod
    def enviar_codigo(cls, session, eid, correo):
        correo = correo.lower().strip()
        mail = cls._obtener_correo_cache(eid)
        if not mail:
            return None
        
        if correo not in mail['email'].lower().strip():
            return None

        codigo = None
        intentos = session.query(ResetClave).filter(ResetClave.correo = correo, ResetClave.confirmado is None).all()
        for rc in intentos:
            codigo = rc.codigo
            break
        else:
            codigo = cls._generar_codigo()

        rid = str(uuid.uuid4())
        rc = ResetClave()
        rc.codigo = codigo
        rc.id = rid
        session.add(rc)

        cls._enviar_codigo_template(codigo, correo)

        return rid