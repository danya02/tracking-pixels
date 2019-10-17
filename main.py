from flask import Flask, make_response, request, render_template, url_for
from peewee import *
from Crypto.Cipher import AES
from Crypto import Random

app = Flask(__name__)

import uuid
import hashlib
import base64
import datetime
import json
import traceback

db = SqliteDatabase('tracking-pixels.db')


class MyModel(Model):
    class Meta:
        database = db

class Pixel(MyModel):
    pixel_id = AutoField()
    name = TextField()
    address = TextField(unique=True)
    description = TextField()
    access_password = BlobField()

class Visit(MyModel):
    visit_id = AutoField
    pixel = ForeignKeyField(Pixel, backref='visits')
    access_date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    user_agent = TextField()
    additional_params = TextField()


db.connect()
db.create_tables([Pixel, Visit])
db.close()

secret_key = Random.new().read(16)

def encrypt(d):
    cipher = AES.new(secret_key, AES.MODE_ECB)
    return cipher.encrypt(d)

def decrypt(d):
    cipher = AES.new(secret_key, AES.MODE_ECB)
    return cipher.decrypt(d)

def hash_password(p):
    return hashlib.scrypt(p, salt=b'SuperCaliFrag1l!st1que_Exp1al1d0c10us!', n=16384, r=8, p=1)


PNG_PIXEL = base64.b64decode(b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP6zwAAAgcBApocMXEAAAAASUVORK5CYII=')

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

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
    kwargs = {'default_address':str(uuid.uuid4()),
            'base_url':url_for('serve_pixel', address='', _external=True)}

    if request.method=='GET':
        return render_template('create_pixel.html', **kwargs)
    try:
        name = request.form['name']
        address = request.form['address']
        description = request.form['description']
        password = hash_password(bytes(request.form['password'],'utf-8'))
        p = Pixel(name=name, address=address, description=description, access_password=password)
        p.save()
        return render_template('create_pixel_result.html', success=True, pixel_url=url_for('serve_pixel', address=address, _external=True), stats_url=url_for('stats', address=address, _external=True), password=request.form['password'], **kwargs)
    except:
        traceback.print_exc()
        return render_template('create_pixel_result.html', success=False, traceback=traceback.format_exc(), **kwargs)

@app.route('/stats/<address>', methods=['GET', 'POST'])
def stats(address):
    try:
        pixel = Pixel.get(Pixel.address==address)
    except DoesNotExist:
        return 'pixel id '+address+' doesnt exist', 404
    if request.method=='GET':
        return render_template('password_validate.html',action='view statistics for '+address, form_action=url_for('stats',address=address))
    if hash_password(bytes(request.form['password'], 'utf-8'))==pixel.access_password:
        enc_password = base64.b64encode(encrypt(pixel.access_password))
        enc_password = str(enc_password, 'utf-8')
        query=Visit.select().where(Visit.pixel == pixel)
        return render_template('view_stats.html', query_result=query,
                enc_password=enc_password,
                name=pixel.name,
                description=pixel.description,
                pixel_id=pixel.pixel_id,
                visit_delete_action=url_for('delete_visit'),
                change_password_action=url_for('change_password'),
                delete_userpage=url_for('delete',address=pixel.address))

    else:
        return 'Password is incorrect, please press the back button and try again', 403

@app.route('/delete/<address>', methods=['GET','POST'])
def delete(address):
    return 'Deletion: To be implemented'

@app.route('/delete_visit', methods=['POST'])
def delete_visit():
    return 'Visit deletion: To be implemented'

@app.route('/change_password', methods=['POST'])
def change_password():
    return 'Password changing: To be implemented'

if __name__ == '__main__':
    app.run()
