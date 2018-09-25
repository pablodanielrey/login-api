from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from model_utils import Base

class ResetClave(Base):

    __tablename__ = 'reset_clave'

    usuario_id = Column(String)
    correo = Column(String)
    codigo = Column(String)
    confirmado = Column(DateTime, nullable=True)
    clave = Column(String)
