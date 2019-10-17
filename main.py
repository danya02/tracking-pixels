from flask import Flask, make_response
from peewee import *

import base64
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
    access_password = CharField()

class Visit(MyModel):
    pixel = ForeignKeyField(Pixel, backref='visits')
    access_date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    user_agent = TextField()
    additional_params = TextField()


db.create_tables([Pixel, Visit])

app = Flask(__name__)

PNG_PIXEL = base64.b64decode(b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP6zwAAAgcBApocMXEAAAAASUVORK5CYII=')

@app.route('/<address>')
def serve_pixel(address):
    # TODO: add tracking here
    response = make_response(PNG_PIXEL)
    response.headers.set('Content-Type', 'image/png')
    return response

@app.route('/create')
def create():
    return 'Creation: To be implemented'

@app.route('/stats/<address>')
def stats(address):
    return 'Statistics: To be implemented'

@app.route('/delete/<address>')
def delete(address):
    return 'Deletion: To be implemented'

if __name__ == '__main__':
    app.run()
