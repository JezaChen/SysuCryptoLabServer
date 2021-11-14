from flask_cors import CORS
from app import create_app
import os

app = create_app()
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port)  # 需要指定host参数为0.0.0.0
