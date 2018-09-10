
import os
import logging
from sqlalchemy import create_engine

from model_utils import Base
from login.model.entities import *

def crear_tablas():
    engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
        os.environ['LOGIN_DB_USER'],
        os.environ['LOGIN_DB_PASSWORD'],
        os.environ['LOGIN_DB_HOST'],
        os.environ.get('LOGIN_DB_PORT', 5432),
        os.environ['LOGIN_DB_NAME']
    ), echo=True)
    Base.metadata.create_all(engine)

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    logging.info('creando tablas')
    crear_tablas()
    logging.info('tablas creadas')
