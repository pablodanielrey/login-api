"""
    https://developers.google.com/admin-sdk/directory/v1/quickstart/python
    https://developers.google.com/resources/api-libraries/documentation/admin/directory_v1/python/latest/
"""

import os
import datetime
import uuid
import logging
import redis

from login.model.entities import UsuarioClave, ResetClave, ErrorGoogle, RespuestaGoogle
from .GoogleAuthApi import GAuthApis


class GoogleModel:

    dominio_primario = os.environ.get('INTERNAL_DOMAINS').split(',')[0]
    admin = os.environ.get('ADMIN_USER_GOOGLE')
    errores_maximos = 5
    REDIS_HOST = os.environ.get('REDIS_HOST','127.0.0.1')
    REDIS_PORT = int(os.environ.get('REDIS_PORT',6379))
    redis = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    if bool(int(os.environ.get('GOOGLE_SYNC',0))):
        service = GAuthApis.getServiceAdmin(admin)
    else:
        service = None

    @classmethod
    def _chequear_errores(cls, session, uid):
        if cls.redis.sismember('google_login_no_sync', uid):
            return True
        errores = session.query(ErrorGoogle).filter(ErrorGoogle.usuario_id == uid).order_by(ErrorGoogle.creado.desc()).all()
        if len(errores) > cls.errores_maximos:
            return True
        if len(errores) <= 0:
            return False
        if errores[0].descripcion == 'Not Found' or errores[0].descripcion == 'Forbidden':
            cls.redis.sadd('google_login_no_sync',uid)
            return True
        return False

    @classmethod
    def _obtener_usuario_google_id(cls, dni):
        return '{}@{}'.format(dni, cls.dominio_primario)

    @classmethod
    def _sincronizar(cls, session, uc):

        assert uc.clave is not None 
        #assert len(uc.clave) >= 8
        clave = uc.clave
        if len(clave) < 8:
            clave = clave + '*' * (8 - len(clave))

        dni = uc.usuario
        usuario_google = cls._obtener_usuario_google_id(dni)

        r = None
        try:
            """ https://developers.google.com/resources/api-libraries/documentation/admin/directory_v1/python/latest/admin_directory_v1.users.html """
            u = cls.service.users().get(userKey=usuario_google).execute()
            datos = {
                'password': clave,
                'changePasswordAtNextLogin': False
            }
            r = cls.service.users().update(userKey=usuario_google,body=datos).execute()
            uc.google = False
            uc.actualizado = datetime.datetime.now()

            rg = RespuestaGoogle()
            rg.usuario_id = uc.usuario_id
            rg.respuesta = r
            session.add(rg)

        except Exception as e:
            er = ErrorGoogle()
            er.usuario_id = uc.usuario_id
            er.error = e.resp.status
            er.descripcion = e.resp.reason
            session.add(er)
            r = er

        return {'sincronizacion_usuario': r }


    @classmethod
    def sincronizar(cls, session, uid):
        assert uid is not None
        u = session.query(UsuarioClave).filter(UsuarioClave.usuario_id == uid, UsuarioClave.eliminada == None).order_by(UsuarioClave.creado.desc()).limit(1).one_or_none()
        if not u:
            return {'uid':uid, 'descripcion':'no existe'}
        return cls._sincronizar(session, u)

    @classmethod
    def sincronizar_dirty(cls, session):
        ''' sincroniza todos los usuarios que esten marcados para google '''
        usuarios = session.query(UsuarioClave).filter(UsuarioClave.google == True, UsuarioClave.eliminada == None).order_by(UsuarioClave.creado.asc()).all()
        sincronizados = []
        for u in usuarios:
            try:
                if cls._chequear_errores(session, u.usuario_id):
                    continue
                ru = cls._sincronizar(session, u)
                session.commit()
                sincronizados.append({'usuario':u.usuario, 'respuesta':ru})
            except Exception as e:
                session.commit()
                logging.exception(e)

        return {
            'usuarios': sincronizados,
            'sincronizados': len(sincronizados)
        }


