import os
import contextlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model_utils import Base
from .entities import *

@contextlib.contextmanager
def obtener_session(echo=True):
    engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
        os.environ['DB_USER'],
        os.environ['DB_PASSWORD'],
        os.environ['DB_HOST'],
        os.environ.get('DB_PORT', 5432),
        os.environ['DB_NAME']
    ), echo=echo)

    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


from .LoginModel import LoginModel
from .RecuperarClaveModel import RecuperarClaveModel

__all__ = [
    'LoginModel',
    'RecuperarClaveModel'
]
