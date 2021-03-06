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
mysqlAddress = "mysql+pymysql://" + EnvVars["MySQLUsername"] + ":" + EnvVars["MySQLPassword"] + "@" + EnvVars["MySQLAddress"] + "/" + EnvVars["DatabaseName"]

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
app.config['JWT_SECRET_KEY'] = EnvVars["JWTSecret"]
app.config['JWT_BLACKLIST_ENABLED'] = False
app.config['JWT_ERROR_MESSAGE_KEY'] = "message"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False


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
api.add_resource(resources.UserLogout, '/v1/logout')
api.add_resource(resources.Edit, '/v1/user/edit')
api.add_resource(resources.ChangePassword, '/v1/user/password')

### User API for getting information:
api.add_resource(resources.AllUsers, '/v1/user')
api.add_resource(resources.GetUid, '/v1/user/uid')
api.add_resource(resources.GetEmail, '/v1/user/email')
api.add_resource(resources.GetUsername, '/v1/user/name')
api.add_resource(resources.GetAll, '/v1/user/all')
api.add_resource(resources.GetPhone, '/v1/user/phone')
api.add_resource(resources.Friend, '/v1/friend')
api.add_resource(resources.FindByUsername, '/v1/user/exists')

# Trip Endpoint
api.add_resource(resources.Trips, '/v1/trip')
api.add_resource(resources.FriendsTrips, '/v1/trip/friends')

if __name__ == '__main__':
    app.run(debug=True)