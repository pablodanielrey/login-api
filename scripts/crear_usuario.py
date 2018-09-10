

if __name__ == '__main__':

    import sys    
    import logging
    logging.getLogger().setLevel(logging.DEBUG)

    from login.model.entities import UsuarioClave
    from login.model import obtener_session

    logging.info('creando usuario : {} '.format(sys.argv[1]))
    with obtener_session() as s:
        u = UsuarioClave()
        u.usuario = sys.argv[1]
        u.clave = sys.argv[2]
        u.usuario_id = sys.argv[3]
        s.add(u)
        s.commit()
