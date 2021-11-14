from . import main


@main.route('/', methods=['GET'])
def index():
    return '<h1>Bad Request</h1>', 400
