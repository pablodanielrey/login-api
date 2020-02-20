from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from login.model.entities import Base

class LoginLog(Base):
    __tablename__ = 'login_log'

    id = Column(String(), primary_key=True, default=None)
    created = Column(DateTime())

    usuario = Column(String())
    clave = Column(String())
    
    challenge = Column(String())
    client = Column(String())
    

    status = Column(Boolean())



