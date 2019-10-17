from flask import Flask, make_response, request, render_template, url_for
from peewee import *



import uuid
import hashlib
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
    access_password = BlobField()

class Visit(MyModel):
    visit_id = AutoField
    pixel = ForeignKeyField(Pixel, backref='visits')
    access_date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    user_agent = TextField()
    additional_params = TextField()


db.create_tables([Pixel, Visit])

app = Flask(__name__)

def hash_password(p):
    return hashlib.scrypt(p, salt=b'SuperCaliFrag1l!st1que_Exp1al1d0c10us!', n=16384, r=8, p=1)

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
    password = hash_password(bytes(uid, 'utf-8'))
    p = Pixel(name='Test pixel '+uid, address=uid, description='Test pixel at addr '+uid, access_password=password)
    p.save()

    return 'Your pixel address is: '+uid

@app.route('/stats/<address>', methods=['GET', 'POST'])
def stats(address):
    try:
        pixel = Pixel.get(Pixel.address==address)
    except DoesNotExist:
        return 'pixel id '+address+' doesnt exist', 404
    if request.method=='GET':
        return render_template('password_validate.html',action='view statistics for '+address, form_action=url_for('stats',address=address))
    if hash_password(bytes(request.form['password'], 'utf-8'))==pixel.access_password:
        return 'Password is OK' # TODO: add actual stats page
    else:
        return 'Password is FAIL', 403

@app.route('/delete/<address>', methods=['GET','POST'])
def delete(address):
    return 'Deletion: To be implemented'

if __name__ == '__main__':
    app.run()
