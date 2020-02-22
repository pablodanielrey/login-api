import os
import contextlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('postgresql://{}:{}@{}:{}/{}'.format(
    os.environ['DB_USER'],
    os.environ['DB_PASSWORD'],
    os.environ['DB_HOST'],
    os.environ.get('DB_PORT', 5432),
    os.environ['DB_NAME']
))

@contextlib.contextmanager
def open_session():
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
