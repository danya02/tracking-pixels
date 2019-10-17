from flask import Flask
from peewee import *
import datetime

db = SqliteDatabase('tracking-pixels.db')
db.connect()
class MyModel(Model):
    class Meta:
        database = db

class Pixel(MyModel):
    pixel_id = AutoField()
    name = CharField()
    address = CharField()
    description = TextField()

class Visit(MyModel):
    pixel = ForeignKeyField(Pixel, backref='visits')
    access_date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    user_agent = TextField()
    additional_params = TextField()


db.create_tables([Pixel, Visit])

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

if __name__ == '__main__':
    app.run()
