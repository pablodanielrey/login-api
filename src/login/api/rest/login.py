
import logging
import datetime
from dateutil.parser import parse
import base64
import io

from flask import Blueprint, jsonify, request, send_file, make_response

from login.api.rest.models import loginModel
from login.model import open_session

bp = Blueprint('login', __name__, url_prefix='/login/api/v1.0')


@bp.route('/device', methods=['POST'])
def get_device_id():
    '''
        Se obtiene un hash para el dispositivo. Se usa en todos las otras apis de login
        respuestas:
            200 - ok
            500 - error irrecuperable
    '''
    try:
        data = request.json
        logging.info(data)

        with open_session() as session:
            #hash_ = loginModel.generate_device(session, data['app_version'], data)
            hash_ = None
            session.commit()

        response = {
            'device_hash': hash_
        }
        return jsonify({'status': 200, 'response': response}), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500

