from app_wrapper import db


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    g = db.Column(db.Text, index=True, nullable=False)
    finished = db.Column(db.Boolean, default=False)
    result = db.Column(db.Text)
    success = db.Column(db.Boolean, default=False)
    operating_time = db.Column(db.Integer, default=0)  # 操作时间
