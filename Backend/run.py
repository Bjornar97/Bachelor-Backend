from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager
from passlib.context import CryptContext
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.debug = True
load_dotenv()

#Getting enviroment variables to avoid having secrets in the code base
EnvVars = os.environ

#Checking if the Enviroment variables exist, and uses them to connect to database. If they were not found, uses default values
mysqlAddress = "mysql://kartapp:" + EnvVars["MySQLPassword"] + "@" + EnvVars["MySQLAddress"] + "/user_table"

if EnvVars["MySQLPassword"] == "":
    print("WARNING: \"MySQLPassword\" Environment variable is not set. Please add the environment variable and restart your computer, see \"setting up dev\" on https://github.com/DAT210/user. MySQL Database now has no password")
    
api = Api(app)

#Setting up sqlalchemy
app.config['SQLALCHEMY_DATABASE_URI'] = mysqlAddress
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

#Adding secret
if EnvVars["Secret"] == "":
    app.config['SECRET_KEY'] = "default-secret"
    print("WARNING: \"userecret\" environment variable is not set! See \"setting up dev\" at https://github.com/DAT210/user for information. Using the default secret(unsecure!)")
else: 
    app.config['SECRET_KEY'] = EnvVars["Secret"]



jwt = JWTManager(app)

#Setting up blacklist
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_ERROR_MESSAGE_KEY'] = "message"

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)


# Setting up passlib
## Making a CryptoContext which is used for password hashing
pwd_context = CryptContext(
    # Schemes secify which hashing algorithm(s) we use
    ## We will use argon2, which is relatively new, and very secure. 
    ## CryptContext has support for multiple hashes to be used like this: shcemes = ["default", "legacy_read_only"]
    schemes = ["argon2"],

    #Deprecated="auto" will mark all but the default hash as deprecated, so it can only be used for reading
    deprecated="auto"
)

import views, models, resources

# Adding routes
## These are located in the resources file

### user actions: 
api.add_resource(resources.UserRegistration, '/v1/registration')
api.add_resource(resources.UserLogin, '/v1/login')
api.add_resource(resources.UserLogoutAccess, '/v1/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/v1/logout/refresh')
api.add_resource(resources.TokenRefresh, '/v1/token/refresh')

### user API for getting information:
api.add_resource(resources.AllUsers, '/v1/user')
api.add_resource(resources.GetUid, '/v1/user/uid')
api.add_resource(resources.GetEmail, '/v1/user/email')
api.add_resource(resources.GetUsername, '/v1/user/name')
api.add_resource(resources.GetAll, '/v1/user/all')
api.add_resource(resources.GetPhone, '/v1/user/phone')
api.add_resource(resources.Edit, '/v1/user/edit')

if __name__ == '__main__':
    app.run(debug=True)