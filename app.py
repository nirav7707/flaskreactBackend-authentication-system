from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS

app=Flask(__name__)
CORS(app)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY']="hvfhberbhvlubtluslrer"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +os.path.join(basedir,'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db = SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    firstname=db.Column(db.String(100))
    lastname=db.Column(db.String(100))
    email=db.Column(db.String(100),unique=True)
    number=db.Column(db.Integer)
    password=db.Column(db.String(100))


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({"message":"Token is missing!"}),401
        try:
            data=jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message":"Token is invalid!"}),401

        return f(current_user,*args,**kwargs)

    return decorated

@app.route("/",methods=['GET'])
@token_required
def dashboard(current_user):
    user={
        "firstname":current_user.firstname,
        "lastname":current_user.lastname,
        "email":current_user.email,
        "number":current_user.number
    }
    return user

@app.route("/users",methods=['GET'])
def get_all_users():
    users = User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['firstname'] = user.firstname
        user_data['lastname'] = user.lastname
        user_data['emai'] = user.email
        user_data['number'] = user.number
        user_data['publicID'] = user.public_id
        output.append(user_data)
    
    return jsonify(output)

@app.route("/login",methods=['POST'])
def login():
    data=request.get_json()

    if not data or not data['email'] or not data['password']:
        return make_response("Could not varify email password",401)
    
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return make_response("Could not verify not in database",401)

    if check_password_hash(user.password,data['password']):
        token = jwt.encode({'public_id':user.public_id,
         'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=5)},
         app.config['SECRET_KEY'],
          algorithm="HS256")
        return jsonify({'token':token})
    return make_response("Could not varify last last last",401)

@app.route("/register",methods=['POST'])
def register():

    data = request.get_json()

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message":"user already exist"})

    if not data['firstname']:
        return make_response('Firstname should not be empty',400)

    if not data['lastname']:
        return make_response('Lastname should not be empty',400)

    if not data['email']:
        return make_response('Emial should not be empty',400)

    if len(str(data['number'])) != 10:
        return make_response('Number must be 10 digit long',400)

    if len(data['password']) <8:
        return make_response('Password must me longer then 8 character',400)
        


    hashed_password = generate_password_hash(data['password'],method='sha256')

    newUser = User(
        public_id=str(uuid.uuid4()),
        firstname=data['firstname'],
        lastname=data['lastname'],
        email=data['email'],
        number=data['number'],
        password=hashed_password
    )
    try:
        db.session.add(newUser)
        db.session.commit()
    except:
        return make_response('something went wrong',400)
    
    return make_response('new user created',200)

    

if __name__=="__main__":
    app.run(debug=True)


