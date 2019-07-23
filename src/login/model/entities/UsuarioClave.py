from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from login.model.entities import Base

import uuid

def generateId():
    return str(uuid.uuid4())

class UsuarioClave(Base):

    __tablename__ = 'usuario_clave'

    id = Column(String, primary_key=True, default=generateId)
    creado = Column(DateTime())
    actualizado = Column(DateTime())

    usuario_id = Column(String, nullable=False)
    usuario = Column(String)
    clave = Column(String)
    expiracion = Column(DateTime)
    eliminada = Column(DateTime)
    debe_cambiarla = Column(Boolean, default=False)
    dirty = Column(Boolean)
    google = Column(Boolean)