import sys
import pandas as pd
import pickle
import datetime
import jwt
from flask import Flask, jsonify, request, make_response
from  flask_sqlalchemy import SQLAlchemy
import warnings
warnings.filterwarnings("ignore")
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from functools import wraps

sys.path.append('../notebook')

#------------------------------------------------------------------------------------------------------------------------------------------------
#DB functions - 

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ZyvO'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/ZYVO_QA_analyticsbox/database/analytical_box.db'

db= SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)
    access = db.Column(db.Boolean)

class Output(db.Model):
    candidate_id = db.Column(db.Integer,primary_key=True)
    organization_name = db.Column(db.String(50),primary_key=True)
    model_name = db.Column(db.String(50),primary_key=True)
    prediction_0 = db.Column(db.String(100))
    prediction_1 = db.Column(db.String(100))
    precision = db.Column(db.Float(50))
    date = db.Column(db.Integer)

class Model(db.Model):
    model_id = db.Column(db.Integer,primary_key=True)
    model_name = db.Column(db.String(50),unique=True)
    hashed_model_name = db.Column(db.String(100))
    model_path = db.Column(db.String(500),unique=True)

class Organization(db.Model):
    organization_id = db.Column(db.Integer,primary_key=True)
    organization_name = db.Column(db.String(50), unique=True)
    hashed_org_name = db.Column(db.String(100))
    model_access = db.Column(db.String(100))
    generalised_model = db.Column(db.String(50))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing.'}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message' : 'Token is invalid.'})
        return f(current_user, *args, **kargs)
    return decorated

#------------------------------------------------------------------------------------------------------------------------------------------------
#User functions - 

@app.route('/user/add', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password, admin=False, access=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created.'})
    
@app.route('/user/all', methods=['GET'])
@token_required
def get_all_users(current_user):  
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['user_id']=user.user_id
        user_data['username']=user.username
        user_data['password']=user.password
        user_data['admin']=user.admin
        user_data['access']=user.access
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<username>', methods=['GET'])
@token_required
def get_one_user(current_user, username):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message' : 'No user found.'})
    user_data = {}
    user_data['user_id']=user.user_id
    user_data['username']=user.username
    user_data['password']=user.password
    user_data['admin']=user.admin
    user_data['access']=user.access
    return jsonify({'user' : user_data})

@app.route('/user/give_access/<username>', methods=['PUT'])
@token_required
def give_user_access(current_user, username):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user'})
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message' : 'No user found.'})
    user.access=True
    db.session.commit()
    return jsonify({'message' : 'Provided access to user.'})

@app.route('/user/delete/<username>', methods=['DELETE'])
@token_required
def delete_user(current_user, username):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message' : 'No user found.'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'User is deleted'})

#------------------------------------------------------------------------------------------------------------------------------------------------
#Organization functions - 

@app.route('/organization/add', methods=['POST'])
@token_required
def add_organization(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    data = request.get_json()
    organization_id = data['organization_id']
    organization_name = data['organization_name']
    model_access = data['model_access']
    generalised_model = data['generalised_model']
    hashed_org_name = hashlib.sha256(organization_name.encode('utf-8')).hexdigest()
    new_organization = Organization(organization_id=organization_id, organization_name=organization_name,\
                                    hashed_org_name=hashed_org_name, model_access=model_access,\
                                    generalised_model=generalised_model)
    db.session.add(new_organization)
    db.session.commit()
    return jsonify({'message' : 'New organization added.'})

@app.route('/organization/all', methods=['GET'])
@token_required
def get_all_organizations(current_user):  
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    organizations = Organization.query.all()
    output = []
    for organization in organizations:
        organization_data = {}
        organization_data['organization_id']=organization.organization_id
        organization_data['organization_name']=organization.organization_name
        organization_data['hashed_org_name']=organization.hashed_org_name
        organization_data['model_access']=organization.model_access
        organization_data['generalised_model']=organization.generalised_model
        output.append(organization_data)
    return jsonify({'organizations' : output})

#------------------------------------------------------------------------------------------------------------------------------------------------
#Model functions - 

@app.route('/model/add', methods=['POST'])
@token_required
def add_model(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    data = request.get_json()
    model_id = data['model_id']
    model_name = data['model_name']
    model_path = data['model_path']
    hashed_model_name = hashlib.sha256(model_name.encode('utf-8')).hexdigest()
    new_model = Model(model_id=model_id, model_name=model_name,\
                      hashed_model_name=hashed_model_name, model_path=model_path)
    db.session.add(new_model)
    db.session.commit()
    return jsonify({'message' : 'New model added.'})

@app.route('/model/all', methods=['GET'])
@token_required
def get_all_models(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    models = Model.query.all()
    output = []
    for model in models:
        model_data = {}
        model_data['model_id']=model.model_id
        model_data['model_name']=model.model_name
        model_data['hashed_model_name']=model.hashed_model_name
        model_data['model_path']=model.model_path
        output.append(model_data)
    return jsonify({'models' : output})

#------------------------------------------------------------------------------------------------------------------------------------------------
#Output functions - 

@app.route('/output/all', methods=['GET'])
@token_required
def get_all_outputs(current_user):  
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    output_scores = Output.query.all()
    output = []
    for output_score in output_scores:
        score_data = {}
        score_data['candidate_id']=output_score.candidate_id
        score_data['organization_name']=output_score.organization_name
        score_data['model_name']=output_score.model_name
        score_data['prediction_0']=output_score.prediction_0
        score_data['prediction_1']=output_score.prediction_1
        score_data['precision']=output_score.precision
        score_data['date']=output_score.date
        output.append(score_data)
    return jsonify({'output_scores' : output})

#------------------------------------------------------------------------------------------------------------------------------------------------
#API functions - 

@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify your login ! Please try again.", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response("Could not verify your login ! Please try again.", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'username' : user.username}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    return make_response("Could not verify your login ! Please try again.", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route('/', methods=['GET'])
@token_required
def home_page(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    response = make_response("Welcome to ZYVO's Analytics Box. \n\n"\
                             "Use /help : to display the help page.")
    response.headers["content-type"] = "text/plain"
    return response

@app.route('/help', methods=['GET'])
@token_required
def help_page(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    response = make_response("Admin+Access (GET) - /login \n" \
                             "Admin(GET) - / \n" \
                             "Admin(GET) - /help \n" \
                             "Admin(POST) - /admin/predict \n" \
                             "Admin+Access(POST) - /predict \n\n" \
                             "Admin(POST) - /user/add \n" \
                             "Admin(GET) - /user/all \n" \
                             "Admin(GET) - /user/<username> \n" \
                             "Admin(PUT) - /user/give_access/<username> \n" \
                             "Admin(DELETE) - /user/delete/<username> \n\n" \
                             "Admin(POST) - /organization/add \n" \
                             "Admin(GET) - /organization/all \n\n" \
                             "Admin(POST) - /model/add \n" \
                             "Admin(GET) - /model/all \n" \
                             "Admin(GET) - /model/<model_id> \n" \
                             "Admin(GET) - /score/<model_id> \n\n" \
                             "Admin(GET) - /output/all \n")
    response.headers["content-type"] = "text/plain"
    return response

@app.route('/model/<model_id>', methods=['GET'])
@token_required
def model_page(current_user, model_id):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    model = get_model(model_id)
    response = make_response("Model : \n" + model.__str__())
    response.headers["content-type"] = "text/plain"
    return response

@app.route('/score/<model_id>', methods=['GET'])
@token_required
def score_page(current_user, model_id):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    score = get_score(model_id)
    response = make_response("Score 80-65-50 : \n" + score.__str__())
    response.headers["content-type"] = "text/plain"
    return response

@app.route('/predict', methods=['POST'])
@token_required
def predict_page(current_user):
    if not current_user.access:
        return jsonify({'message' : 'User does not have access.'})
    today = datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    output_dict = {}
    json_input = request.get_json(silent=True)
    model_id = json_input['model_id']
    try:
        model = get_model(model_id)
        model_name = get_model_name(model_id)
    except:
        return jsonify({'message' : 'Model_id details are not present in model table.'})
    organization_id = json_input['organization_id']
    try:
        organization_name = get_org_name(organization_id)
    except:
        return jsonify({'message' : 'Organization_id details are not present in organization table.'})
    if not check_model_access(model_id, organization_id):
        return jsonify({'message' : 'The Organization does not have access to the model.'})
    df_test_post = pd.DataFrame(json_input['scores'], index=[0])
    prediction = model.predict_proba(df_test_post).tolist()[0]
    prediction_0,prediction_1 = prediction
    precision = get_precision(model_id, prediction_1)
    output_dict['candidate_id'] = json_input['candidate_id']
    output_dict['prediction'] = prediction
    output_dict['precision'] = precision
    try:
        new_output = Output(candidate_id=output_dict['candidate_id'], organization_name=organization_name, \
                            model_name=model_name, prediction_0=prediction_0, prediction_1=prediction_1, \
                            precision=output_dict['precision'], date=today)
        db.session.add(new_output)
        db.session.commit()
    except:
        return jsonify(output_dict)
    return jsonify(output_dict)

@app.route('/admin/predict', methods=['POST'])
@token_required
def predict_admin_page(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Not an admin user.'})
    output_dict = {}
    json_input = request.get_json(silent=True)
    model_id = json_input['model_id']
    try:
        model = get_model(model_id)
    except:
        return jsonify({'message' : 'Model_id details are not present in model table.'})
    df_test_post = pd.DataFrame(json_input['scores'], index=[0])
    prediction = model.predict_proba(df_test_post).tolist()[0]
    prediction_0,prediction_1 = prediction
    precision = get_precision(model_id, prediction_1)
    output_dict['candidate_id'] = json_input['candidate_id']
    output_dict['prediction'] = prediction
    output_dict['precision'] = precision
    return jsonify(output_dict)

#------------------------------------------------------------------------------------------------------------------------------------------------
# Custom functions

def get_model_path(model_id):
    model = Model.query.filter_by(model_id=model_id).first()
    return model.model_path

def get_model(model_id):
    with open(get_model_path(model_id) ,'rb') as model_file:
        model = pickle.load(model_file)
    return model['Classifier']

def get_score(model_id):
    with open(get_model_path(model_id) ,'rb') as score_file:
        score = pickle.load(score_file)
    return score['Confidence_Proba']

def get_org_name(organization_id):
    organization = Organization.query.filter_by(organization_id=organization_id).first()
    return organization.organization_name

def get_org_hashed(organization_id):
    organization = Organization.query.filter_by(organization_id=organization_id).first()
    return organization.hashed_org_name

def get_model_name(model_id):
    model = Model.query.filter_by(model_id=model_id).first()
    return model.model_name

def get_model_hashed(model_id):
    model = Model.query.filter_by(model_id=model_id).first()
    return model.hashed_model_name

def check_model_access(model_id, organization_id):
    organization = Organization.query.filter_by(organization_id=organization_id).first()
    model_access = str(organization.model_access)
    return model_id in model_access.split(',')    

def get_precision(model_id, prediction_1):
    precision = 0
    score = get_score(model_id) 
    if((prediction_1>0.80) | (prediction_1<0.20)):
        precision = score[0]
    elif((prediction_1>0.35) & (prediction_1<0.65)):
        precision = score[2]
    else: #((prediction[1].between(0.65,0.80)) | (prediction[1].between(0.20,0.35))):
        precision = score[1]
    return precision
    
#------------------------------------------------------------------------------------------------------------------------------------------------
# Main function
    
if __name__ == '__main__':
    app.run(port=8000)