import os
import contextlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model_utils import Base
from .entities import *

@contextlib.contextmanager
def obtener_session(echo=True):
    engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
        os.environ['LOGIN_DB_USER'],
        os.environ['LOGIN_DB_PASSWORD'],
        os.environ['LOGIN_DB_HOST'],
        os.environ.get('LOGIN_DB_PORT', 5432),
        os.environ['LOGIN_DB_NAME']
    ), echo=echo)

    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

__all__ = [
    'LoginModel',
    'RecuperarClaveModel'
]
