from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from model_utils import Base

class UsuarioClave(Base):

    __tablename__ = 'usuario_clave'

    usuario_id = Column(String, nullable=False)
    usuario = Column(String)
    clave = Column(String)
