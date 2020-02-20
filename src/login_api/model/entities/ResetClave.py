from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from login.model.entities import Base

import uuid

def generateId():
    return str(uuid.uuid4())
    
class Recover(Base):

    __tablename__ = 'reset_clave'

    id = Column(String, primary_key=True, default=generateId)
    creado = Column(DateTime())
    actualizado = Column(DateTime())

    usuario_id = Column(String)
    correo = Column(String)
    codigo = Column(String)
    confirmado = Column(DateTime, nullable=True)
    clave = Column(String)
