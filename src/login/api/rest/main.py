# -*- coding: utf-8 -*-
'''
    Confiruro los loggers
'''
import logging
logging.getLogger().setLevel(logging.DEBUG)

import sys
import os
from dateutil import parser

from werkzeug.contrib.fixers import ProxyFix

import flask
from flask import Flask, Response, abort, make_response, jsonify, url_for, request, json, stream_with_context
from flask_jsontools import jsonapi
from dateutil import parser

VERIFY_SSL = bool(int(os.environ.get('VERIFY_SSL',0)))
OIDC_ADMIN_URL = os.environ['OIDC_ADMIN_URL']

from rest_utils import register_encoder

client_id = os.environ['OIDC_CLIENT_ID']
client_secret = os.environ['OIDC_CLIENT_SECRET']
oidc_url = os.environ['OIDC_URL']

warden_url = os.environ['WARDEN_API_URL']
from warden.sdk.warden import Warden
warden = Warden(oidc_url, warden_url, client_id, client_secret, verify=VERIFY_SSL)

from login.model import obtener_session, LoginModel, RecuperarClaveModel

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.wsgi_app = ProxyFix(app.wsgi_app)
register_encoder(app)

API_BASE = os.environ['API_BASE']

@app.route(API_BASE + '/acceso_modulos', methods=['GET'])
@warden.require_valid_token
@jsonapi
def obtener_acceso_modulos(token=None):

    prof = warden.has_one_profile(token, ['assistance-super-admin'])
    if prof and prof['profile'] == True:
        a = [
            'super-admin'
        ]
        return json.dumps(a)

    prof = warden.has_one_profile(token, ['assistance-admin'])
    if prof and prof['profile'] == True:
        a = [
            'inicio_personal',
            'reporte_personal',
            'reporte_general',
            'reporte_detalles_avanzados',
            'justificacion_personal',
            'justificacion_general',
            'justificacion_tipo_abm',
            'horario_vista',
            'horario_abm'
        ]
        return json.dumps(a)
    
    prof = warden.has_one_profile(token, ['assistance-operator'])
    if prof and prof['profile'] == True:
        a = [
            'inicio_personal',
            'reporte_personal',
            'reporte_general',
            'reporte_detalles_avanzados',
            'justificacion_personal',
            'justificacion_general',
            'horario_vista'
        ]
        return json.dumps(a)

    a = [
        'inicio_personal'
    ]
    return json.dumps(a)            

@app.route(API_BASE + '/init_login_flow/<challenge>', methods=['GET'])
@jsonapi
def init_login_flow(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.init_login_flow(challenge)

@app.route(API_BASE + '/login', methods=['POST'])
@jsonapi
def login():
    data = request.get_json()
    if not data or ('usuario' not in data and 'clave' not in data and 'challenge' not in data):
        return ('Datos no válidos', 401)
    logging.info(data)
    u = data['usuario']
    c = data['clave']
    challenge = data['challenge']
    with obtener_session(False) as s:
        try:
            r = LoginModel.login(s, u, c, challenge)
            return r
        except Exception as e:
            logging.exception(e)
            return (str(e),401)
    return ('inválido',401)


@app.route(API_BASE + '/init_consent_flow/<challenge>', methods=['GET'])
@jsonapi
def init_consent_flow(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.init_consent_flow(challenge)


"""
    métodos dedicados al manejo de sesion
"""
@app.route(API_BASE + '/logout/<id_token>/<client_id>', methods=['GET'])
@jsonapi
def logout(id_token, client_id):
    if not id_token or not client_id:
        return ('invalid', 401)
    
    return {'status_code':200}

@app.route(API_BASE + '/usuario/<uid>/generar_clave', methods=['GET'])
@warden.require_valid_token
@jsonapi
def usuario_generar_clave(uid, token):
    if not uid:
        return ('invalid', 401)
    
    return {'uid':'', 'clave':''}



"""
    los siguientes son métodos de la interface de hydra.
    para herramientas de administracion
"""

@app.route(API_BASE + '/sessions/<uid>', methods=['GET'])
@warden.require_valid_token
@jsonapi
def get_user_sessions(uid, token=None):
    if not uid:
        return ('invalid', 401)
    return LoginModel.obtener_sesiones_usuario(uid)

@app.route(API_BASE + '/sessions/<uid>', methods=['DELETE'])
@jsonapi
def delete_user_sessions(uid):
    if not uid:
        return ('invalid', 401)
    LoginModel.eliminar_sesiones_usuario(uid)
    return {'status_code':200}

@app.route(API_BASE + '/sessions/<uid>/<cid>', methods=['DELETE'])
@jsonapi
def delete_user_client_sessions(uid, cid):
    if not uid or not cid:
        return ('invalid', 401)
    LoginModel.eliminar_sesiones_usuario_cliente(uid, cid)
    return {'status_code':200}


"""
    los métodos siguientes son para el manejo de recuperación de clave.
"""
RC_BASE = API_BASE + '/recuperar_clave'

@app.route(RC_BASE + '/verificar_dni/<dni>', methods=['GET'])
@jsonapi
def verificar_dni(dni):
    assert dni is not None
    with obtener_session(False) as s:
        u = RecuperarClaveModel.verificar_dni(dni)
        r = None
        if not u:
            r = {
                'ok': False,
                'error': {'error':'200', 'descripcion':'No existe ese dni'}
            }
        else:
            r = {
                'ok':True,
                'tiene_correo': u['tiene_correo'],
                'usuario': u['usuario']
            }
        return r

@app.route(RC_BASE + '/obtener_correo/<uid>', methods=['GET'])
@jsonapi
def obtener_correo(uid):
    assert uid is not None
    with obtener_session(False) as s:
        c = RecuperarClaveModel.obtener_correo(uid)
        r = None
        if not c:
            r = {
                'ok': False,
                'error': {'error':'200', 'descripcion':'no se pudo obtener la información de correo'}
            }
        else:
            r = {
                'ok':True,
                'correo': c['correo'],
                'usuario': c['usuario']
            }
        return r

@app.route(RC_BASE + '/enviar_codigo/<eid>', methods=['POST'])
@jsonapi
def enviar_codigo(eid):
    assert eid is not None
    data = request.get_json()
    assert 'correo' in data

    with obtener_session(False) as s:
        c = RecuperarClaveModel.enviar_codigo(s, eid, data['correo'])
        s.commit()
        r = None
        if not c:
            r = {
                'ok': False,
                'error': {'error':'200', 'descripcion':'no se pudo enviar el correo'}
            }
        else:
            r = {
                'ok':True,
                'iid':c
            }
        return r              


@app.route(RC_BASE + '/verificar_codigo/<iid>', methods=['POST'])
@jsonapi
def verificar_codigo(iid):
    assert iid is not None
    data = request.get_json()
    assert 'codigo' in data

    with obtener_session(False) as s:
        c = RecuperarClaveModel.verificar_codigo(s, iid, data['codigo'])
        s.commit()
        r = None
        if not c:
            r = {
                'ok': False,
                'error': {'error':'200', 'descripcion':'código incorrecto'}
            }
        else:
            r = {
                'ok':True,
                'clave':c
            }
        return r 

"""
@app.route(API_BASE + '/login/<challenge>', methods=['GET'])
@jsonapi
def get_login_challenge(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.obtener_login_challenge(challenge)

@app.route(API_BASE + '/login/<challenge>/accept', methods=['PUT'])
@jsonapi
def accept_login_challenge(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.aceptar_login_challenge(challenge)

@app.route(API_BASE + '/consent/<challenge>', methods=['GET'])
@jsonapi
def get_consent_challenge(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.obtener_consent_challenge(challenge)

@app.route(API_BASE + '/consent/<challenge>/accept', methods=['PUT'])
@jsonapi
def accept_consent_challenge(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.aceptar_consent_challenge(challenge)
"""


@app.route(API_BASE + '*', methods=['OPTIONS'])
def options():
    if request.method == 'OPTIONS':
        return 204
    return 204

@app.after_request
def cors_after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')

    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers['Cache-Control'] = 'public, max-age=0'

    return response

def main():
    app.run(host='0.0.0.0', port=10002, debug=False)

if __name__ == '__main__':
    main()
