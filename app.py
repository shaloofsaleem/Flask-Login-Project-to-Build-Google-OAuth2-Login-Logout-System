import json
import os
import sqlite3

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Third party libraries
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# Internal imports
from db import init_db_command
from user import User

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return "You Must Be logged in",403
try:
    init_db_command()
except sqlite3.OperationalError:
    pass
client = WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def user_loder(user_id):
    return User.get(user_id)

@app.route("/")
def index():
    if current_user.is_authenticated:
        return(
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
            current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        print(GOOGLE_CLIENT_ID)
        return '<a href="/login"><button>Google Login</button></a>'

@app.route('/login')
def login():
    google_provider_cfg = get_google_provider_cfg()
    
    authorization_endpoint = google_provider_cfg['authorization_endpoint']
    
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri= request.base_url+ '/callback',
        scope= ['openid', 'email','profile']
        
    ) 
    return redirect(request_uri)

@app.route('/login/callback')
def callback():
    code = request.args.get('code')
    google_provider_cfg =get_google_provider_cfg()
    
    token_endpoint = get_google_provider_cfg['token_endpoint']
    
    token_url,headers,body =client.prepare_token_request(
        token_endpoint,
        authorization_response= request.url,
        redirect_url=request.base_url,
        code =code
    )
    token_response =requests.post(
        token_url,
        headers=headers,
        data = body,
        auth = (GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET)
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    
    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body =client.add_token(userinfo_endpoint)
    
    userinfo_response = requests.get(
        uri ,
        headers=headers,
        data = body
    )
    print(userinfo_response.json())
    
    if userinfo_response.json().get('Email_verifed'):
        unique_id =userinfo_response.json()['sub']
        users_email =userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        users_name = userinfo_response.json()['givenname']
    else:
        return 'User Email not avaliable or not verified by google',400
    user = User(
        id_=unique_id,
        name = users_name,
        email= users_email,
        profile_pic=picture,
    )
    if not User.get(unique_id):
        User.create(unique_id,
                    users_name,
                    users_email,
                    picture,
                    )
        login_user(user)
        return redirect(url_for('index'))
@app.route('/logout')
def logout ():
    logout_user
    return redirect(url_for= 'index')
    
    
def get_google_provider_cfg():
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    
    

if __name__ == "__main__":
    app.run(debug=True)