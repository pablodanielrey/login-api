from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from login.model.entities import Base

class UsuarioClave(Base):

    __tablename__ = 'usuario_clave'

    usuario_id = Column(String, nullable=False)
    usuario = Column(String)
    clave = Column(String)
    expiracion = Column(DateTime)
    eliminada = Column(DateTime)
    debe_cambiarla = Column(Boolean, default=False)
    dirty = Column(Boolean)
    google = Column(Boolean)