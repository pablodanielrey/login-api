
import logging
import datetime
from dateutil.parser import parse
import base64
import io

from flask import Blueprint, jsonify, request, send_file, make_response

from login.api.rest.models import loginModel
from login.model import open_session

bp = Blueprint('recover', __name__, url_prefix='/recover/api/v1.0')


@bp.route('/recover/<user>', methods=['POST'])
def recover_for(user):
    try:
        data = request.json
        assert 'device' in data and data['device'] is not None

        """
            se registra un hash para iniciar el proceso de recuperación.
            los datos que se guardan son:
            hash -- user -- device -- email -- code
        """ 
        response = {
            'hash': 'ef32f0j392fj3ofm32f',
            'email': 'pab***@****.edu.ar',
            'device': data['device'],
            'user': user
        } 

        response = {
            'status': 200,
            'response': response
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


@bp.route('/check_code/<code>', methods=['POST'])
def check_code(code):
    try:
        data = request.json
        assert 'hash' in data and data['hash'] is not None

        """
            se chequea el codigo generado en el paso anterior con el codigo enviado ahora.

            hash == data['hash']
            code == data['code']
        """

        response = {
            'status': 200,
            'response': 'code ok'
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


@bp.route('/credentials', methods=['POST'])
def change_credentials():
    try:
        data = request.json
        assert 'hash' in data and data['hash'] is not None
        assert 'credentials' in data and data['credentials'] is not None

        """
            se reemplaza la clave por la clave enviada en credentials
        """

        response = {
            'status': 200,
            'response': 'ok'
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500
