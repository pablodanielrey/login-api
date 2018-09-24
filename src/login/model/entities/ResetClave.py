from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from model_utils import Base

class ResetClave(Base):

    __tablename__ = 'reset_clave'

    correo = Column(String)
    codigo = Column(String)
    confirmado = Column(DateTime, nullable=True)
    
    