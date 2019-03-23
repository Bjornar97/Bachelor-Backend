from flask_restful import Resource, reqparse
from models import User, WhiteTokenModel
import random
import json
from run import app
import re

from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

registration_parser = reqparse.RequestParser()
registration_parser.add_argument('email', help = 'This field cannot be blank', required = True)
registration_parser.add_argument('password', help = 'This field cannot be blank', required = True)
registration_parser.add_argument('username', help = 'This field can be blank', required = False)
registration_parser.add_argument('birthday', help = 'This field can be blank', required = False)
registration_parser.add_argument('phone', help = 'This field can be blank', required = False)
registration_parser.add_argument('city', help = 'This field can be blank', required = False)


# Registration
## URI: /registration
class UserRegistration(Resource):
    def post(self):
        data = registration_parser.parse_args()

        if not data["email"]:
            return {'message': 'Email is required'}

        if not data["password"]:
            return {'message': 'Password is required'}

        # Checking if the email is already in our database, returns message if it is. Countinues if not.
        if User.find_by_email(data['email']):
            return {'message': 'User {} already exists'. format(data['email'])}, 401

        if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
            return {'message': 'Eposten er ugyldig'}, 401

        # Hashing password as soon as possible, Please dont add anything between the line above and below this comment
        data["password"] = User.generate_hash(data["password"])

        #TODO: Improve this \/
        uid = random.randint(10000000, 99999999)
        while User.find_by_uid(uid):
            if uid >= 99999999:
                uid = 10000000
            else:
                uid += 1
        
        # Making a new model with the email and password provided
        new_user = User(
            user_id = uid,
            user_email = data["email"],
            user_password = data["password"],
            user_name = data["username"],
            user_birthday = data["birthday"],
            user_phone = data["phone"],
            user_city = data["city"]
        )

        try:
            # Saving the new user to the database. the method is located in models.py
            new_user.save_to_db()

            # Making tokens so the User is logged in
            access_token = create_access_token(identity = uid)

            whitelist_token = WhiteTokenModel(jti = access_token["jti"])
            whitelist_token.add()

            return {
                'message': 'User {} was created'.format( data['email']),
                'access_token': access_token
            }, 201
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500

# Login
## URI: /login
class UserLogin(Resource):
    def post(self):
        data = registration_parser.parse_args()

        # Finding User from the database
        current_user = User.find_by_email(data['email'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['email'])}
        
        # Checking password, if correct, it makes tokens to log the User in
        if User.verify_hash(data["password"], current_user.user_password):
            access_token = create_access_token(identity = current_user.user_id)
            whitelist_token = WhiteTokenModel(jti = access_token["jti"])
            whitelist_token.add()
            return {
                'message': 'Logged in as {}'.format(current_user.user_email),
                'access_token': access_token
            }, 202
        else:
            return {'message': 'Wrong email or password'}, 401

## URI: /logout
class UserLogout(Resource):
    # Requires a jwt object to run, which basically means that the User must be logged in to log out(which makes sense)
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            whitelist_token = WhiteTokenModel(jti = jti)
            whitelist_token.remove(jti)
            return {'message': 'Access token has been revoked'}, 200
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500

#Only for testing purposes
## TODO: (IMPORTANTE) Delete "AllUsers" class before production!
class AllUsers(Resource):
    def get(self):
        if app.debug == True:
            return User.return_all(), 200
        else:
            return "You are not allowed to get all customers", 403
    
    def delete(self):
        if app.debug == True:
            print("Got into delete")
            return User.delete_all(), 200
        else:
            return "You are not allowed to delete all customers", 403


# The following classes are for the Api

edit_parser = reqparse.RequestParser()
edit_parser.add_argument('password', help = 'This field can be blank', required = False)
edit_parser.add_argument('username', help = 'This field can be blank', required = False)
edit_parser.add_argument('birthday', help = 'This field can be blank', required = False)
edit_parser.add_argument('phone', help = 'This field can be blank', required = False)
edit_parser.add_argument('city', help = 'This field can be blank', required = False)

## URI: /v1/user/edit
class Edit(Resource):
    @jwt_required
    def post(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401

        data = edit_parser.parse_args()
        
        # Getting the uid from the jwt.
        current_user = get_jwt_identity()

        # Getting the User from the database through the model in models.py
        user_object = User.find_by_uid(current_user)
        
        # Hashing password as soon as possible, Please dont add anything between the line above and below this comment
        data["password"] = User.generate_hash(data["password"])

        # Checks if no object got returned in the query, then return 401 Unauthorized.
        if user_object.user_id == None:
            return {"message": "Invalid uid. The User doesn't exist in our database"}, 401

        if data["password"]:
            user_object.user_password = data["password"]
        if data["username"]:
            user_object.user_name = data["user_name"]
        if data["birthday"]:
            user_object.user_birthday = data["birthday"]
        if data["phone"]:
            user_object.user_phone = data["phone"]
        if data["city"]:
            user_object.city = data["city"]

        try:
            # Saving the new user to the database. the method is located in models.py

            return {
                'message': 'User {} was edited'.format(user_object.user_email),
            }, 201
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500

## URI: /v1/user/uid
class GetUid(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401
        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the User from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The User doesnt exist in our database"}, 401

            return {"message": "The uid was found", 
                "uid": current_user
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500

## URI: /v1/user/email
class GetEmail(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the User from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The User doesnt exist in our database"}, 401
            
            return {"message": "Email of the User was found", "email": user_object.user_email}, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500


## URI: /v1/user/phone
class GetPhone(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object.user_id == None:
                return {"message": "Invalid uid. The user doesn't exist in our database"}, 401
            
            return {"message": "Phone of the user was found", "phone": user_object.user_phone}, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500

## URI: /v1/user/name
class GetUsername(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The user doesnt exist in our database"}, 401

            return {"message": "Name of the user was found", 
                "username": user_object.user_name 
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500

## URI: /v1/user/all
class GetAll(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 401
        
        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object.user_id == None:
                return {"message": "Invalid uid. The user doesn't exist in our database"}, 401


            return {"message": "user was found", 
                "uid": current_user,
                "email": user_object.user_email,
                "username": user_object.user_name, 
                "birthday": user_object.user_birthday,
                "phone": user_object.user_phone,
                "city": user_object.city
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500