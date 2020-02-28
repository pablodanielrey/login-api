
import logging
import datetime
from dateutil.parser import parse
import base64
import io
import os

from flask import Blueprint, jsonify, request, send_file, make_response

from login.model import obtener_session as login_open_session
from users.model import open_session as users_open_session

from login_api.api.rest.models import loginModel
from login_api.api.rest.models import mailsModel

from login_api.model import open_session
from login_api.model.RecoverModel import RecoverModel

INTERNAL_DOMAINS = os.environ['INTERNAL_DOMAINS'].split(',')
RESET_FROM = os.environ['RESET_CREDENTIALS_FROM']

bp = Blueprint('email', __name__, url_prefix='/email/api/v1.0')

@bp.route('/configure/<user>', methods=['POST'])
def recover_for(user):
    try:
        data = request.json
        assert data and 'device' in data and data['device'] is not None
        assert data and 'email' in data and data['email'] is not None
        assert data and 'user' in data and data['user'] is not None

        device = data['device']

        """
            Se genera un registro de confirmación de correo alternativo.
        """ 
                
        with users_open_session() as user_session:
            with open_session() as recover_session:
                try:
                    model = RecoverModel(recover_session, user_session, loginModel, mailsModel, INTERNAL_DOMAINS, RESET_FROM)
                    r = model.recover_for(user, device)
                    recover_session.commit()

                    response = {
                        'status': 200,
                        'response': r
                    }
                    return jsonify(response), 200

                except Exception as e:
                    recover_session.rollback()
                    response = {
                        'status': 400,
                        'response': str(e)
                    }
                    return jsonify(response), 200

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


@bp.route('/verify_code/<code>', methods=['POST'])
def verify_code(code):
    try:
        data = request.json
        assert data and 'user' in data and data['user'] is not None
        assert data and 'device' in data and data['device'] is not None

        """
            se chequea el codigo generado en el paso anterior con el codigo enviado ahora.
            user_identity_number = data['user']
        """

        user = data['user']

        with users_open_session() as user_session:
            with open_session() as recover_session:
                try:
                    model = RecoverModel(recover_session, user_session, loginModel, mailsModel, INTERNAL_DOMAINS, RESET_FROM)
                    r = model.verify_code(user, code)
                    recover_session.commit()

                    response = {
                        'status': 200,
                        'response': {
                            'session':r
                        }
                    }
                    return jsonify(response), 200

                except Exception as e:
                    recover_session.rollback()
                    response = {
                        'status': 400,
                        'response': str(e)
                    }
                    return jsonify(response), 200        

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500


@bp.route('/credentials', methods=['POST'])
def change_credentials():
    try:
        data = request.json
        assert 'session' in data and data['session'] is not None
        assert 'credentials' in data and data['credentials'] is not None

        """
            se reemplaza la clave por la clave enviada en credentials
            session = id de la entidad CredentialsReset
        """
        session = data['session']
        credentials = data['credentials']

        with open_session() as recover_session:
            try:
                model = RecoverModel(recover_session, None, loginModel, mailsModel, INTERNAL_DOMAINS, RESET_FROM)
                cid = model.change_credentials(session, credentials)
                recover_session.commit()

                response = {
                    'status': 200,
                    'response': {
                        'session':cid
                    }
                }
                return jsonify(response), 200

            except Exception as e:
                recover_session.rollback()
                response = {
                    'status': 400,
                    'response': str(e)
                }
                return jsonify(response), 200                

    except Exception as e:
        return jsonify({'status': 500, 'response':str(e)}), 500
