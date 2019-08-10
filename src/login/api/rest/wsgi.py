import logging
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger().propagate = True


from flask import Flask
from flask_cors import CORS
from werkzeug.contrib.fixers import ProxyFix

app = Flask(__name__)
app.debug = False
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app)

"""
    registro el encoder para json
"""

from login.model.entities import AlchemyEncoder
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

from . import login

app.register_blueprint(login.bp)
