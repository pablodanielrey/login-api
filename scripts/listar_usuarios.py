

if __name__ == '__main__':

    import sys    
    from login.model.entities import UsuarioClave
    from login.model import obtener_session

    with obtener_session() as s:
        for uc in s.query(UsuarioClave).all():
            print(uc.__json__())
