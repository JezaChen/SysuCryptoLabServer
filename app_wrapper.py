from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from app import create_app
from flask_migrate import Migrate
from server_secrets import POSTGRESQL_URL

app = create_app()
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config[
    'SQLALCHEMY_DATABASE_URI'
] = POSTGRESQL_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
