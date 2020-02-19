
import logging
import datetime
from dateutil.parser import parse
import base64
import io

from flask import Blueprint, jsonify, request, send_file, make_response

from login.api.rest.models import loginModel
from login.model import open_session

bp = Blueprint('credentials', __name__, url_prefix='/credentials/api/v1.0')


""" requiere usuario autentificado """
@bp.route('/change', methods=['POST'])
def change():
    try:
        data = request.json
        assert 'device' in data and data['device'] is not None
        assert 'user' in data and data['user'] is not None
        assert 'credentials' in data and data['credentials'] is not None

        """
            cambia la clave de un usuario
            envía un correo indicando la situación
        """

        response = {
            'status': 200,
            'response': 'ok'
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


@bp.route('/temporal', methods=['POST'])
def check_if_temporal():
    try:
        data = request.json
        assert 'device' in data and data['device'] is not None
        assert 'user' in data and data['user'] is not None

        """
            chequea si las credenciales de un usuario son temporal
        """

        response = {
            'status': 200,
            'response': False
        }
        return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


