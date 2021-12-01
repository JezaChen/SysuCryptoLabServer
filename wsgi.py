import os

import app_wrapper
import database

app = app_wrapper.app
db = app_wrapper.db
migrate = app_wrapper.migrate

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port)  # 需要指定host参数为0.0.0.0
