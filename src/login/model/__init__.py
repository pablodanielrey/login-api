import os
import contextlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model_utils import Base
from .entities import *

@contextlib.contextmanager
def obtener_session():
    engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
        os.environ['LOGIN_DB_USER'],
        os.environ['LOGIN_DB_PASSWORD'],
        os.environ['LOGIN_DB_HOST'],
        os.environ.get('LOGIN_DB_PORT', 5432),
        os.environ['LOGIN_DB_NAME']
    ), echo=True)

    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()



from .LoginModel import LoginModel

__all__ = [
    'LoginModel'
]

def crear_tablas():
    engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
        os.environ['LOGIN_DB_USER'],
        os.environ['LOGIN_DB_PASSWORD'],
        os.environ['LOGIN_DB_HOST'],
        os.environ.get('LOGIN_DB_PORT', 5432),
        os.environ['LOGIN_DB_NAME']
    ), echo=True)
    Base.metadata.create_all(engine)