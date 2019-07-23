import datetime
from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_
from sqlalchemy.orm import relationship

from login.model.entities import Base

import uuid

def generateId():
    return str(uuid.uuid4())

class ErrorGoogle(Base):

    __tablename__ = 'error_google'

    id = Column(String, primary_key=True, default=generateId)
    creado = Column(DateTime())
    actualizado = Column(DateTime())

    usuario_id = Column(String)
    error = Column(String)
    descripcion = Column(String)

class RespuestaGoogle(Base):

    __tablename__ = 'respuesta_google'

    id = Column(String, primary_key=True, default=generateId)
    creado = Column(DateTime())
    actualizado = Column(DateTime())    

    usuario_id = Column(String)
    respuesta = Column(String)
