from flask import Flask, make_response, abort, request, render_template, url_for, session, redirect, flash
from peewee import *

app = Flask(__name__)

app.config['SECRET_KEY'] = 'So secret, much spoopy'
import datetime
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=5)

import time
import uuid
import hashlib
import base64
import json
import traceback
from functools import wraps

db = SqliteDatabase('tracking-pixels.db')


class MyModel(Model):
    class Meta:
        database = db

class User(MyModel):
    email = CharField(unique=True)
    password = BlobField()
    username = CharField(unique=True)
    

class Pixel(MyModel):
    owner = ForeignKeyField(User, backref='pixels')
    pixel_id = AutoField()
    name = TextField()
    address = CharField(unique=True)
    description = TextField()

class Visit(MyModel):
    visit_id = AutoField()
    pixel = ForeignKeyField(Pixel, backref='visits')
    access_date = DateTimeField(default=datetime.datetime.now)
    ip_address = IPField()
    user_agent = TextField()
    additional_params = TextField()

class Access(MyModel):
    name = TextField()
    pixel = ForeignKeyField(Pixel, backref='accesses')
    access_date = BooleanField(default=True)
    ip_address = BooleanField(default=True)
    user_agent = BooleanField(default=True)
    additional_params = BooleanField(default=True)
    readable_rows = IntegerField(default=0)
    password = BlobField()
    address = CharField(unique=True)
    




db.connect()
db.create_tables([Pixel, Visit, User, Access])
db.close()


def hash_password(p):
    if isinstance(p, bytes):
        return hashlib.scrypt(p, salt=b'SuperCaliFrag1l!st1que_Exp1al1d0c10us!', n=16384, r=8, p=1)
    else:
        return hashlib.scrypt(bytes(p, 'utf-8'), salt=b'SuperCaliFrag1l!st1que_Exp1al1d0c10us!', n=16384, r=8, p=1)


# from https://stackoverflow.com/a/5333305
def readable_delta(from_seconds, until_seconds=None):
    '''Returns a nice readable delta.

    readable_delta(1, 2)           # 1 second ago
    readable_delta(1000, 2000)     # 16 minutes ago
    readable_delta(1000, 9000)     # 2 hours, 133 minutes ago
    readable_delta(1000, 987650)   # 11 days ago
    readable_delta(1000)           # 15049 days ago (relative to now)
    '''

    if not until_seconds:
        until_seconds = time.time()

    seconds = until_seconds - from_seconds
    delta = datetime.timedelta(seconds=seconds)

    # deltas store time as seconds and days, we have to get hours and minutes ourselves
    delta_minutes = delta.seconds // 60
    delta_hours = delta_minutes // 60

    ## show a fuzzy but useful approximation of the time delta
    if delta.days:
        return '%d day%s, ' % (delta.days, plur(delta.days)) + '%d hour%s, %d minute%s ago' % (delta_hours % 24, plur(delta_hours), delta_minutes, plur(delta_minutes))
    elif delta_hours:
        return '%d hour%s, %d minute%s ago' % (delta_hours, plur(delta_hours), delta_minutes%60, plur(delta_minutes))
    elif delta_minutes:
        return '%d minute%s ago' % (delta_minutes, plur(delta_minutes))
    else:
        return '%d second%s ago' % (delta.seconds, plur(delta.seconds))

def plur(it):
    '''Quick way to know when you should pluralize something.'''
    try:
        size = len(it)
    except TypeError:
        size = int(it)
    return '' if size==1 else 's'



PNG_PIXEL = base64.b64decode(b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP6zwAAAgcBApocMXEAAAAASUVORK5CYII=')

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

@app.route('/<path:address>', methods=['GET','POST'])
def serve_pixel(address):
    if request.method=='POST': # then it could only have come from an access
        try:
            access = Access.get(Access.address==address)
        except DoesNotExist: 
            return abort(404)
        return serve_access(access, post=True)

    try:
        pixel = Pixel.get(Pixel.address==address) # if this is a pixel, we need its model for logging
    except DoesNotExist: # but it may also be an access because they share a namespace
        try:
            access = Access.get(Access.address==address)
            return serve_access(access)
        except DoesNotExist: # and if there isn't an access either
            pass # may return error here instead, but focus on concealment of pixel -- if this errors while embedded, the pixel may be visible as a placeholder
    else:
        if Visit.select().where(Visit.pixel == pixel).count()==0:
            pass # TODO: do something interesting if it's the first visit on this pixel
        visit = Visit(pixel=pixel, user_agent=request.headers.get('User-Agent', None), ip_address=request.remote_addr, additional_params=json.dumps(request.args))
        visit.save()
    response = make_response(PNG_PIXEL)
    response.headers.set('Content-Type', 'image/png')
    return response


def serve_access(access, post=False):
    if access.password!=b'':
        if post:
            try:
                if hash_password(request.form['password']) == access.password:
                    return serve_access_authed(access)
                else:
                    return render_template('password_validate.html', action='visit pixel stats by access', form_action=url_for('serve_pixel', address=access.address), fail=True)
            except:
                return render_template('password_validate.html', action='visit pixel stats by access', form_action=url_for('serve_pixel', address=access.address), fail=True)
    
        else:
            return render_template('password_validate.html', action='visit pixel stats by access', form_action=url_for('serve_pixel', address=access.address), fail=False)
    else:
        return serve_access_authed(access)

def serve_access_authed(access):
    return render_template('stats_access.html', pixel=access.pixel, access=access, Visit=Visit)


@app.route('/register/', methods=['GET','POST'])
def register():
    if request.method=='GET':
        return render_template('registration_form.html')
    if request.form['referral']!='AmuseYourFriends_ConfoundYourEnemies':
        return render_template('registration_form_failure.html', error='Referral password is incorrect. Please contact the administrator or another user of the website for access to it.')
    try:
        user = User.create(username=request.form['username'], email=request.form['email'], password=hash_password(request.form['password']))
        user.save()
    except IntegrityError:
        return render_template('registration_form_failure.html', error='A user with this username and/or email already exists.')


    session.permanent = True
    session['username'] = user.username
    
    redir = url_for('dashboard')

    return redirect(redir, code=303)


def needs_auth(func):
    @wraps(func)
    def authed_func(*args, **kwargs):
        redir_addr = request.script_root+request.full_path
        redir_addr = redir_addr.lstrip('/')
        try:
            if session.new == False and session['username']:
                try:
                    user = User.select().where(User.username==session['username']).get()
                    return func(*args, **kwargs, user=user)
                except User.DoesNotExist:
                    del session['username']
                    session.permanent = False
                    return redirect(url_for('login', redir=redir_addr), code=303)
        except KeyError:
            return redirect(url_for('login', redir=redir_addr), code=303)
    return authed_func


@app.route('/dashboard/')
@needs_auth
def dashboard(user=None):
    return render_template('dashboard.html', user=user, uuid=uuid, Visit=Visit, datetime=datetime, readable_delta=readable_delta)

def to_dash():
    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@needs_auth
def change_password(user=None):
    if user.password == hash_password(request.form['old-password']):
        user.password = hash_password(request.form['new-password'])
        user.save()
        flash('Your password has been successfully altered!')
    else:
        flash('Your old password was not correct.')
    return to_dash()

@app.route('/create-pixel', methods=['POST'])
@needs_auth
def create_pixel(user=None):
    p = Pixel(name=request.form['name'],
            owner=user,
            address=request.form['endpoint'],
            description='No description set yet, replace this with your description!')
    p.save()
    return to_dash()

@app.route('/destroy-pixel/', methods=['POST'])
@needs_auth
def delete_pixel(user=None):
    try:
        pid = int(request.form['pixel-id'])
    except:
        flash('Your request to delete a pixel was malformed. Are you a dirty hacker?')
        return to_dash()
    try:
        pixel = Pixel.get(Pixel.pixel_id==int(request.form['pixel-id']))
    except Pixel.DoesNotExist:
        flash('This pixel does not exist. Has it already been deleted?')
        return to_dash()
    if pixel.owner != user:
        flash('You do not own this pixel. Have you re-authorized in another tab?')
        return to_dash()
    Visit.delete().where(Visit.pixel==pixel).execute()
    pixel.delete_instance()
    return to_dash()

@app.route('/stats/<address>')
def stats(address):
    try:
        pixel = Pixel.get(Pixel.address==address)
    except Pixel.DoesNotExist:
        flash('This pixel does not exist. Has it been deleted recently?')
        return to_dash()
    return render_template('stats.html', pixel=pixel, uuid=uuid, bytes=bytes)

@app.route('/destroy-visit/', methods=['POST'])
@needs_auth
def delete_visit(user=None):
    try:
        pixel_id = int(request.form['pixel-id'])
        visit_id = int(request.form['visit-id'])
    except:
        flash('Your request to delete a visit is malformed. Are you a dirty hacker?')
        return to_dash()
    try:
        pixel = Pixel.get(Pixel.pixel_id==pixel_id)
    except Pixel.DoesNotExist:
        flash('This pixel does not exist. Has it been recently deleted?')
        return to_dash()

    if pixel.owner != user:
        flash('This pixel does not belong to you. Have you re-authorized in another tab?')
        return to_dash()

    redir = redirect(url_for('stats', address=pixel.address))

    try:
        visit = Visit.get(Visit.visit_id==visit_id)
    except Visit.DoesNotExist:
        flash('The visit to be deleted does not exist. Has it been deleted already?')
        return redir
    if visit.pixel != pixel:
        flash('This visit does not belong to the pixel the client thinks it belongs to. Are you a dirty hacker?')
        return redir
    visit.delete_instance()
    return redir

@app.route('/alter-pixel', methods=['POST'])
@needs_auth
def alter_pixel(user=None):
    try:
        pid = int(request.form['pixel-id'])
    except:
        flash('Your request to alter a pixel was malformed. Are you a dirty hacker?')
        return to_dash()
    try:
        pixel = Pixel.get(Pixel.pixel_id==int(request.form['pixel-id']))
    except Pixel.DoesNotExist:
        flash('This pixel does not exist. Has it already been deleted?')
        return to_dash()
    if pixel.owner != user:
        flash('You do not own this pixel. Have you re-authorized in another tab?')
        return to_dash()

    try:
        pixel.name = request.form['name']
        pixel.description = request.form['description']
        if len(request.form['endpoint'])>240:
            raise KeyError('endpoint too long')
        pixel.address = request.form['endpoint']
    except KeyError as k:
        flash('Necessary field of alter pixel form ('+k.args[0]+') was missing or invalid. Are you a dirty hacker?')
        return redirect(url_for('stats', address=pixel.address))
    pixel.save()
    return redirect(url_for('stats', address=pixel.address))

@app.route('/create_access/', methods=['POST'])
@needs_auth
def create_access(user=None): 
    try:
        pid = int(request.form['pixel_id'])
    except:
        flash('Your request to create an access did not include a proper pixel id. Are you a dirty hacker?')
        return to_dash()
    try:
        pixel = Pixel.get(Pixel.pixel_id==pid)
    except Pixel.DoesNotExist:
        flash('The relevant pixel does not exist. Has it been recently deleted?')
        return to_dash()
    redir = redirect(url_for('stats', address=pixel.address))
    vals = dict()
    try:
        for i in ['name','readable-rows','password','endpoint']:
            vals[i]=request.form[i]
    except KeyError as k:
        flash('One of the expected fields in the form ('+k.args[0]+') was not present. Are you a dirty hacker?')
        return redir
    if pixel.owner != user:
        flash('This pixel does not belong to you. Have you re-authorized from another tab?')
        return to_dash()
    try:
        vals['readable-rows'] = int(vals['readable-rows'])
    except:
        flash('A value that was expected to be numeric was not. Are you a dirty hacker?')
    try:
        try:
            Pixel.get(Pixel.address==vals['endpoint'])
        except:pass
        else: raise IntegrityError
        
        if 'access_id' in request.form:
            access = Access.get(Access.id==request.form['access_id'])
        else:
            access = Access(pixel=pixel, name=vals['name'], readable_rows=vals['readable-rows'], password=hash_password(vals['password']) if vals['password']!='' else b'', address=vals['endpoint'])
    except IntegrityError:
        flash('This endpoint is already used by a different access or a pixel, please try a different one.')
        return redir
    except ValueError:
        flash('An id value was not numeric. Are you a dirty hacker?')
        return redir
    except Access.DoesNotExist:
        flash('This acccess does not exist. Has it been deleted recently?')
        return redir
    values =  {'access-time':'access_date', 'ip-addr': 'ip_address', 'useragent': 'user_agent', 'get-params':'additional_params'}
    print(request.form)
    for i in values:
        if i in request.form:
            print(i,'ON')
            access.__setattr__(values[i], True)
        else:
            print(i,'OFF')
            access.__setattr__(values[i], False)
    access.address = request.form['endpoint']
    access.name=request.form['name']
    access.readable_rows=request.form['readable-rows']
    if request.form['password']=='':
        access.password=b''
    elif request.form['password']=='KeepThePasswordTheSameAsItWasBefore':
        pass
    else:
        access.password=hash_password(request.form['password'])
    access.save()
    return redir


@app.route('/destroy-access/', methods=['POST'])
@needs_auth
def delete_access(user=None):
    try:
        pixel_id = int(request.form['pixel-id'])
        access_id = int(request.form['access-id'])
    except:
        flash('Your request to delete an access is malformed. Are you a dirty hacker?')
        return to_dash()
    try:
        pixel = Pixel.get(Pixel.pixel_id==pixel_id)
    except Pixel.DoesNotExist:
        flash('This pixel does not exist. Has it been recently deleted?')
        return to_dash()

    if pixel.owner != user:
        flash('This pixel does not belong to you. Have you re-authorized in another tab?')
        return to_dash()

    redir = redirect(url_for('stats', address=pixel.address))

    try:
        access = Access.get(Access.id==access_id)
    except Visit.DoesNotExist:
        flash('The access to be deleted does not exist. Has it been deleted already?')
        return redir
    if access.pixel != pixel:
        flash('This access does not belong to the pixel the client thinks it belongs to. Are you a dirty hacker?')
        return redir
    access.delete_instance()
    return redir
    

@app.route('/logout/')
def log_out():
    session.permanent = None
    try:
        del session['username']
    except KeyError:
        pass
    return redirect(url_for('login'))
        

@app.route('/login/', methods=['GET','POST'])
@app.route('/login/<path:redir>', methods=['GET','POST'])
def login(redir=None):
    try:
        if session.new == False and session['username']:
            try:
                user = User.select().where(User.username==session['username']).get()
                if not redir: redir = url_for('dashboard')
                return redirect(redir, code=303)
            
            except User.DoesNotExist:
                del session['username']
                session.permanent = False
    except KeyError:
        pass
    if request.method == 'GET':
        return render_template('login_form.html')
    uname = request.form['username']
    try:
        user = User.get(User.username==uname or User.email == uname)
    except User.DoesNotExist:
        return render_template('login_form_failure.html', error='User not found, please register first.')
    if user.password!=hash_password(request.form['password']):
        return render_template('login_form_failure.html', error='Password incorrect, please try again.')
    session.permanent = True
    session['username'] = user.username

    if not redir: redir = url_for('dashboard')

    return redirect(redir, code=303)



if __name__ == '__main__':
    app.run(debug=True, port=5001)
