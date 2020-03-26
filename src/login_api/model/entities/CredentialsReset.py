import uuid
from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, func, or_

from . import Base


def generateId():
    return str(uuid.uuid4())
    
class CredentialsReset(Base):

    __tablename__ = 'credentials_reset'

    id = Column(String, primary_key=True, default=generateId)
    created = Column(DateTime())
    updated = Column(DateTime())
    deleted = Column(DateTime())

    is_internal = Column(Boolean, default=False)
    user_id = Column(String)
    username = Column(String)
    email = Column(String)
    code = Column(String)
    verified = Column(DateTime, nullable=True)
