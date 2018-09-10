

if __name__ == '__main__':

    from pprint import pprint
    import sys    
    from login.model.entities import Sesion
    from login.model import obtener_session

    with obtener_session(False) as s:
        for uc in s.query(Sesion).all():
            pprint(uc.__json__())
