

if __name__ == '__main__':
    from login_api.model.entities.CredentialsReset import CredentialsReset
    from login_api.model.entities import Base
    from login_api.model import engine
    Base.metadata.create_all(engine)