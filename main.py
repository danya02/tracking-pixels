from flask import Flask, make_response, request
from peewee import *
import uuid

import base64
import datetime
import json

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
    try:
        pixel = Pixel.get(Pixel.address==address)
    except DoesNotExist:
        return 'pixel id '+address+' doesnt exist', 404
    if Visit.select().where(Visit.pixel == pixel).count()==0:
        pass # TODO: do something interesting if it's the first visit on this pixel
    visit = Visit(pixel=pixel, user_agent=request.headers.get('User-Agent', None), ip_address=request.remote_addr, additional_params=json.dumps(request.args))
    visit.save()
    response = make_response(PNG_PIXEL)
    response.headers.set('Content-Type', 'image/png')
    return response

@app.route('/create', methods=['GET','POST'])
def create():
    uid = str(uuid.uuid4())
    p = Pixel(name='Test pixel '+uid, address=uid, description='Test pixel at addr '+uid, access_password=uid)
    p.save()

    return 'Your pixel address is: '+uid

@app.route('/stats/<address>')
def stats(address):
    return 'Statistics: To be implemented'

@app.route('/delete/<address>', methods=['GET','POST'])
def delete(address):
    return 'Deletion: To be implemented'

if __name__ == '__main__':
    app.run()
