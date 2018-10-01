
import os
import datetime
import hashlib
import requests
import logging
import redis
import json
import uuid

from sqlalchemy import or_

import oidc
from oidc.oidc import ClientCredentialsGrant

from .entities import UsuarioClave, ResetClave
from .HydraModel import HydraModel
from .MailsModel import MailsModel

class RecuperarClaveModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 0)))
    INTERNAL_DOMAINS = os.environ['INTERNAL_DOMAINS'].split(',')
    OIDC_URL = os.environ['OIDC_URL']
    OIDC_ADMIN_URL = os.environ['OIDC_ADMIN_URL']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']
    REDIS_HOST = os.environ.get('REDIS_HOST','127.0.0.1')
    REDIS_PORT = int(os.environ.get('REDIS_PORT',6379))
    RESET_CLAVE_FROM = os.environ.get('RESET_CLAVE_FROM','')
    
    USERS_API_URL = os.environ['USERS_API_URL']

    grant = ClientCredentialsGrant(OIDC_URL, client_id, client_secret, verify=verify)
    redis = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    """
    ////////////// MANEJO DE CACHE ////////////////////////
    """

    @classmethod
    def _obtener_usuario_api(cls, url, token=None):
        if not token:
            token = cls._obtener_token()
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }        
        r = requests.get(url, headers=headers, verify=cls.verify, allow_redirects=False)
        if not r.ok:
            logging.debug(r)
            raise Exception('error obteniendo usuario')
        usr = r.json()
        if not usr:
            return None
        assert 'id' in usr
        cls._setear_usuario_cache(usr)
        return usr

    @classmethod
    def _setear_usuario_cache(cls, usr):
        expire = 60 * 5
        uid = usr['id']
        kmails = 'r_usuario_mails_{}'.format(uid)
        cls.redis.delete(kmails)
        for m in usr['mails']:
            mid = m['id']
            k = 'r_mail_{}'.format(mid)
            cls.redis.hmset(k, m)
            cls.redis.expire(k, expire * 2)
            cls.redis.sadd(kmails, mid)
        cls.redis.expire(kmails, expire * 2)

        k = 'r_usuario_uid_{}'.format(uid)
        cls.redis.hmset(k, usr)
        cls.redis.expire(k, expire)

        k = 'r_usuario_dni_{}'.format(usr['dni'].lower().replace(' ',''))
        cls.redis.hset(k, 'uid', uid)
        cls.redis.expire(k, expire)

    @classmethod
    def _eliminar_usuario_de_cache(cls, uid):
        k = 'r_usuario_mails_{}'.format(uid)
        cls.redis.delete(k)
        k = 'r_usuario_uid_{}'.format(uid)
        cls.redis.delete(k)

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
        if not usr:
            return None
        c = cls._obtener_correo_alternativo(usr)
        if c:
            return {'tiene_correo':True, 'usuario':usr}
        else:
            return {'tiene_correo':False, 'usuario':usr}

    @classmethod
    def obtener_correo(cls, uid):
        usr = cls._obtener_usuario_por_uid(uid)
        if not usr:
            raise Exception('No existe ese usuario')
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
    def _enviar_codigo_template(cls, usuario, codigo, correo):
        templ = MailsModel.obtener_template('codigo.tmpl')
        text = templ.render(usuario=usuario, codigo=codigo)
        r = MailsModel.enviar_correo(cls.RESET_CLAVE_FROM,correo,'Reseteo de Clave FCE', text)
        if r.ok:
            logging.debug('correo enviado correctamente')
        else:
            logging.debug('error enviando correo')

    @classmethod
    def enviar_codigo(cls, session, eid, correo):
        correo = correo.lower().strip()
        mail = cls._obtener_correo_cache(eid)
        if not mail:
            return None
        
        if correo not in mail['email'].lower().strip():
            return None

        uid = mail['usuario_id']
        usuario = cls._obtener_usuario_por_uid(uid)
        if not usuario:
            return None

        codigo = None
        intentos = session.query(ResetClave).filter(ResetClave.correo == correo, ResetClave.confirmado == None).all()
        for rc in intentos:
            codigo = rc.codigo
            break
        else:
            codigo = cls._generar_codigo()

        rid = str(uuid.uuid4())
        rc = ResetClave()
        rc.codigo = codigo
        rc.correo = correo
        rc.usuario_id = uid
        rc.id = rid
        session.add(rc)

        cls._enviar_codigo_template(usuario, codigo, correo)

        return rid

    @classmethod
    def _generar_clave(cls):
        return str(uuid.uuid4())[:8]


    @classmethod
    def _enviar_clave_template(cls, usuario, clave, correo):
        templ = MailsModel.obtener_template('clave_temporal.tmpl')
        text = templ.render(usuario=usuario, clave=clave)
        r = MailsModel.enviar_correo(cls.RESET_CLAVE_FROM,correo,'Reseteo de Clave FCE', text)
        if r.ok:
            logging.debug('correo enviado correctamente')
        else:
            logging.debug('error enviando correo')

    @classmethod
    def _cambiar_clave(cls, session, usuario, clave, es_temporal=True):

        uid = usuario['id']
        dni = usuario['dni']
        cs = session.query(UsuarioClave).filter(UsuarioClave.usuario_id == uid).all()
        for c in cs:
            c.eliminada = datetime.datetime.now()
        
        uc = UsuarioClave()
        uc.usuario_id = uid
        uc.usuario = dni
        uc.clave = clave
        uc.dirty = True
        uc.debe_cambiarla = es_temporal
        if es_temporal:
            uc.expiracion = datetime.datetime.now() + datetime.timedelta(days=5)
        else:
            ''' a google solo se sincronizan las claves que no son temporales '''
            uc.google = True
        session.add(uc)


    @classmethod
    def verificar_codigo(cls, session, iid, codigo):
        assert iid is not None
        assert codigo is not None

        rc = session.query(ResetClave).filter(ResetClave.id == iid, ResetClave.codigo == codigo).one_or_none()
        if not rc:
            return None

        uid = rc.usuario_id
        correo = rc.correo

        usuario = cls._obtener_usuario_por_uid(uid)
        if not usuario:
            raise Exception('no se pudo obtener el usuario')

        confirmado = datetime.datetime.now()
        actualizado = datetime.datetime.now()
        clave = cls._generar_clave()
        
        cls._cambiar_clave(session, usuario, clave, es_temporal=True)

        rcs = session.query(ResetClave).filter(ResetClave.codigo == codigo, ResetClave.correo == correo).all()
        for rc in rcs:
            rc.actualizado = actualizado
            rc.confirmado = confirmado
            rc.clave = clave

        session.commit()

        try:
            cls._enviar_clave_template(usuario, clave, correo)
        except Exception as e:
            logging.exception(e)

        try:
            cls._eliminar_usuario_de_cache(uid)
        except Exception as e:
            logging.exception(e)

        return clave

    @classmethod
    def cambiar_clave(cls, session, uid, clave, es_temporal=False):
        usuario = cls._obtener_usuario_por_uid(uid)
        if not usuario:
            raise Exception('no se pudo obtener el usuario')
        cls._cambiar_clave(session, usuario, clave, es_temporal)

    @classmethod
    def recuperar_cambiar_clave(cls, session, cid, clave):
        """
            Para permitir varios tipos de flujos, el verificar código genera una clave temporal
            y este método permite cambiar la clave temporal por una fija, si es que como cid se pasa la temporal.
        """
        uc = session.query(UsuarioClave).filter(UsuarioClave.clave == cid).one()
        uid = uc.usuario_id
        cls.cambiar_clave(session, uid, clave, es_temporal=False)


    @classmethod
    def precondiciones(cls, session, uid):
        ''' por ahora solo chequeo que no tenga clave temporal '''
        ahora = datetime.datetime.now()
        q = session.query(UsuarioClave).filter(UsuarioClave.usuario_id == uid, UsuarioClave.eliminada == None)
        #existe un problema con la zona horaria de la fecha por lo que siempre da expirada. asi que por ahora lo comento
        #q.filter(or_(UsuarioClave.debe_cambiarla == True, UsuarioClave.expiracion <= ahora))
        q = q.filter(UsuarioClave.debe_cambiarla == True)
        claves_temporales = q.count()
        return {
            'clave': claves_temporales <= 0
        }
