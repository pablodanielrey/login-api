import logging
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger().propagate = True


from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.debug = False
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app)

"""
    registro el encoder para json
"""

from login_api.model.entities import AlchemyEncoder
app.json_encoder = AlchemyEncoder

"""
    /////////////
    registro los converters 
"""
from rest_utils.converters.ListConverter import ListConverter
app.url_map.converters['list'] = ListConverter
"""
    ////////////
"""

from . import recover
from . import credentials

app.register_blueprint(recover.bp)
app.register_blueprint(credentials.bp)
