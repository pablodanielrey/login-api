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

from rest_utils import register_encoder

import oidc
from oidc.oidc import TokenIntrospection
client_id = os.environ['OIDC_CLIENT_ID']
client_secret = os.environ['OIDC_CLIENT_SECRET']
rs = TokenIntrospection(client_id, client_secret, verify=VERIFY_SSL)

warden_url = os.environ['WARDEN_API_URL']
from warden.sdk.warden import Warden
warden = Warden(warden_url, client_id, client_secret, verify=VERIFY_SSL)

from login.model import obtener_session, LoginModel

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.wsgi_app = ProxyFix(app.wsgi_app)
register_encoder(app)

API_BASE = os.environ['API_BASE']

@app.route(API_BASE + '/acceso_modulos', methods=['GET'])
@rs.require_valid_token
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

@app.route(API_BASE + '/login', methods=['POST'])
@jsonapi
def login():
    data = request.get_json()
    if not data or ('usuario' not in data and 'clave' not in data):
        return ('Datos no válidos', 401)
    logging.info(data)
    u = data['usuario']
    c = data['clave']
    with obtener_session(False) as s:
        try:
            token = LoginModel.login(s, u, c)
            s.commit()
            return {
                'status':200,
                'session':token
            }
        except Exception as e:
            logging.exception(e)
            return (str(e),401)
    return ('inválido',401)

@app.route(API_BASE + '/login_challenge/<challenge>', methods=['GET'])
@jsonapi
def login_challenge(challenge):
    if not challenge:
        return ('invalid', 401)
    return LoginModel.chequear_login_challenge(challenge)

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
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    main()
