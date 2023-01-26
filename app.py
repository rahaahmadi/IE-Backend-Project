from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import jwt
from functools import wraps
from  werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import threading, schedule, requests
import mysql.connector,requests

app  = Flask(__name__)
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@127.0.0.1/web_db' 
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, username, password):
        self.username = username
        self.password = password

class Url(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),  server_default=func.now())
    threshold = db.Column(db.Integer, nullable=False)
    failed_times = db.Column(db.Integer, default=0)
    
    def __init__(self, address, threshold, user_id) :
        self.address = address
        self.threshold = threshold
        self.user_id = user_id

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    result = db.Column(db.Integer)
    
    
    def __init__(self, url_id, result) :
        self.url_id = url_id
        self.result = result

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Authentication Token is missing'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id = data['id']).first()
        except:
            return jsonify({'message' : 'Invalid Authentication token!'}), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

# signup route
@app.route('/signup', methods =['POST'])
def signup():

    data = request.form
  
    username = data.get('username')
    password = data.get('password')
  
    # checking for existing user
    user = User.query.filter_by(username = username).first()
    if not user:
        # database ORM object
        user = User(
            username=username,
            password = generate_password_hash(password, method='sha256')
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        # generate JWT Token
        token = jwt.encode({'id': user.id, 'exp' : datetime.utcnow() + timedelta(minutes = 45)}, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token, 'message': 'Successfully registered.'}), 201)
  
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    auth = request.form
  
    if not auth or not auth.get('username') or not auth.get('password'):
        # returns 401 if any username or password is missing
        return make_response('Could not verify', 401, {'Authentication': 'login required'})
  
    user = User.query.filter_by(username = auth.get('username')).first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response('Could not verify', 401, {'Authentication': 'User does not exist'})
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({'id': user.id, 'exp' : datetime.utcnow() + timedelta(minutes = 45)}, app.config['SECRET_KEY'])

        return make_response(jsonify({'token' : token}), 201)
    # returns 403 if password is wrong
    return make_response('Could not verify', 403, {'Authentication' : 'Wrong Password'}
    )

# route for urls
@app.route('/urls', methods =['POST','GET'])
@token_required
def urls(user):
    if request.method == 'GET':
        urls = Url.query.filter_by(user_id = user.id).all()
        res = []
        for url in urls:
            url_data = {}
            url_data['id'] = url.id
            url_data['address'] = url.address
            url_data['threshold'] = url.threshold
            
            res.append(url_data)
        
        return jsonify({'users': res})

    else:
        data = request.form

        address = data.get('address')
        threshold = data.get('threshold')

        if(address == None or threshold == None):
            return jsonify({'message' : 'Address and Threshold are required.'}), 400
        if(not re.compile("https?://[\w]*[.][\w]*").match(address)):
            return jsonify({'message' : 'Url format is not correct'}), 400
        
        url = Url(address,threshold,user.id)
        db.session.add(url)
        db.session.commit()
        return jsonify({'message' : 'url added successfully.'}), 201

@app.route('/urls/<url_id>', methods =['GET'])
@token_required
def url_requests(url_id):
    from_date = datetime(year=datetime.now().year, month=datetime.now().month, day=1)

    requests = Request.query.filter_by(url_id=url_id).filter(Request.created_at >= from_date).all()
    res = []
    for request in requests:
        data = {}
        url = Url.query.filter_by(id=request.url_id).first()
        data['url'] = url.address
        data['result_code'] = request.result
        data['created_at'] = request.created_at
        
        res.append(data)
    
    return jsonify({'users': res})


@app.route('/alerts', methods =['GET'])
@token_required
def alerts():
    urls = Url.query.filter(Url.failed_times>=Url.threshold).all()
    res = []
    for url in urls:
        res.append(url.address)
    response = {'failed_urls':res}
    if (len(res) > 0):
        response['alert_message'] = 'Url(s) has reached maximum failure.'
    print(response)
    return jsonify(response),201

def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()

def request_periodically():
    database = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        database="web_db"
)
    cursor = database.cursor()
    try :
        cursor.execute('SELECT * FROM url')
        result = cursor.fetchall()

        for x in result:
            url = x[1]
            req = requests.get(url)
            status_code = req.status_code
            cursor.execute(f'INSERT INTO request (url_id, code) VALUES ({x[0]}, {status_code})')
            database.commit()
            if status_code < 200 or status_code >= 300:
                cursor.execute(f'UPDATE url SET failed_times = failed_times+1 where id={x[0]}')
            database.commit()
    except :
        print('Error')
    database.close()

if __name__ == "__main__":
    threading.Thread(target = app.run()).start()
    
    schedule.every(60).seconds.do(run_threaded, request_periodically)    
    while True:
        schedule.run_pending()