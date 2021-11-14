from . import main


@main.route('/', methods=['GET'])
def index():
    return '<h1>Bad Request</h1>', 400


@main.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
