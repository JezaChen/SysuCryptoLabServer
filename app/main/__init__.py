from flask import Blueprint

main = Blueprint('main', __name__)

from . import index, utils, rsa_simple_oaep_interface, rsa_es_oaep_interface
