from app import create_app
from flask_cors import CORS

app = create_app()
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

if __name__ == '__main__':
    app.run(host="0.0.0.0")  # 需要指定host参数为0.0.0.0
