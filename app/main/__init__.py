from flask import Blueprint

main = Blueprint('main', __name__)

from . import index, utils, rsa_simple_oaep_interface, rsa_es_oaep_interface
from .dlp import dlp_interface
from .dsa import dsa_interface
from .prg import prg_interface