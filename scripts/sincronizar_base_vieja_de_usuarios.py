
if __name__ == '__main__':

    import sys
    from sqlalchemy import  or_
    from login.model.entities import UsuarioClave
    from login.model import obtener_session


    import logging
    logging.getLogger().setLevel(logging.DEBUG)
    import os
    import psycopg2

    with obtener_session() as s:

        con = psycopg2.connect("host={} port={} dbname={} user={} password={}".format(
            os.environ['OLD_USERS_DB_HOST'],
            os.environ['OLD_USERS_DB_PORT'],
            os.environ['OLD_USERS_DB_NAME'],
            os.environ['OLD_USERS_DB_USER'],
            os.environ['OLD_USERS_DB_PASSWORD']))
        cur = con.cursor()
        cur.execute('select id, user_id, username, password, expiracion, eliminada, debe_cambiarla, creado, actualizado from user_password')
        for c in cur:

            cid = c[0]
            creado = c[7]
            actualizado = c[8]
            cu = s.query(UsuarioClave).filter(UsuarioClave.id == cid).one_or_none()
            if cu:
                if cu.actualizado != actualizado and cu.creado != creado and (cu.actualizado < actualizado or cu.creado < creado):
                    uc.clave = c[3]
                    uc.expiracion = c[4]
                    uc.eliminada = c[5]
                    uc.debe_cambiarla = c[6]
                    uc.actualizado = actualizado
                    uc.creado = creado
                    s.commit()
            else:
                uc = UsuarioClave()
                uc.id = cid
                uc.usuario_id = c[1]
                uc.usuario = c[2]
                uc.clave = c[3]
                uc.expiracion = c[4]
                uc.eliminada = c[5]
                uc.debe_cambiarla = c[6]
                uc.creado = creado
                uc.actualizado = actualizado
                s.add(uc)
                s.commit()
               

