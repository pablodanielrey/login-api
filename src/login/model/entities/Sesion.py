import os
import datetime
from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from model_utils import Base

EXPIRACION = int(os.environ.get('SESSION_EXPIRATION', 3600))

def _ahora():
    return datetime.datetime.now()

def _obtener_expiracion():
    return datetime.datetime.now() + datetime.timedelta(seconds=EXPIRACION)

class Sesion(Base):

    __tablename__ = 'sesiones'

    usuario_clave_id = Column(String)
    fecha = Column(DateTime(timezone=True), default=_ahora)
    expirado = Column(DateTime(timezone=True), default=_obtener_expiracion)
    token = Column(String)

