from flask_restful import Resource, reqparse
from flask import request
from models import User, WhiteTokenModel, Friends, Trip
import random
import json
from run import app
import re

from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt, get_jti)

registration_parser = reqparse.RequestParser()
registration_parser.add_argument('email', help = 'This field cannot be blank', required = True)
registration_parser.add_argument('password', help = 'This field cannot be blank', required = True)
registration_parser.add_argument('username', help = 'This field cannot be blank', required = True)

registration_parser.add_argument('phone', help = 'This field can be blank', required = False)

# Registration
## URI: /registration
class UserRegistration(Resource):
    def post(self):
        data = registration_parser.parse_args()

        # Checking if the email is already in our database, returns message if it is. Countinues if not.
        if User.find_by_email(data['email']):
            return {'message': 'User with email {} already exists'. format(data['email']), 'emailExists': True}, 203

        if User.find_by_username(data['username']):
            return {'message': 'Bruker {} finnes allerede'. format(data['username']), 'usernameExists': True}, 203

        # TODO: Check username

        if not re.match(r"^[a-zA-Z0-9]*$", data["username"]):
            return {'message': 'Brukernavn er ugyldig, kan kun inneholde alfanumeriske tegn', "usernameInvalid": True}, 205


        if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
            return {'message': 'Eposten er ugyldig', "emailInvalid": True}, 205

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
            user_phone = data["phone"]
        )

        try:
            # Saving the new user to the database. the method is located in models.py
            new_user.save_to_db()

            # Making tokens so the User is logged in
            access_token = create_access_token(identity = uid)

            whitelist_token = WhiteTokenModel(jti = get_jti(access_token))
            whitelist_token.add()

            return {
                'message': 'User {} was created'.format( data['email']),
                'access_token': access_token
            }, 201
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500

login_parser = reqparse.RequestParser()
login_parser.add_argument('loginName')
login_parser.add_argument('password')

# Login
## URI: /login
class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()

        # Finding User from the database
        if re.match(r"[^@]+@[^@]+\.[^@]+", data["loginName"]):
            current_user = User.find_by_email(data['loginName'])
        else:
            current_user = User.find_by_username(data['loginName'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['loginName'])}, 203
        
        # Checking password, if correct, it makes tokens to log the User in
        if User.verify_hash(data["password"], current_user.user_password):
            access_token = create_access_token(identity = current_user.user_id)

            whitelist_token = WhiteTokenModel(jti = get_jti(access_token))
            whitelist_token.add()
            
            return {
                'message': 'Logged in as {}'.format(current_user.user_name),
                'access_token': access_token
            }, 202
        else:
            return {'message': 'Wrong email or password'}, 203

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
edit_parser.add_argument('email', help = 'This field can be blank', required = False)
edit_parser.add_argument('phone', help = 'This field can be blank', required = False)

## URI: /v1/user/edit
class Edit(Resource):
    @jwt_required
    def post(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205

        data = edit_parser.parse_args()
        
        # Getting the uid from the jwt.
        current_user = get_jwt_identity()

        # Getting the User from the database through the model in models.py
        user_object = User.find_by_uid(current_user)
        
        # Checks if no object got returned in the query, then return 401 Unauthorized.
        if user_object.user_id == None:
            return {"message": "Invalid uid. The user doesn't exist in our database"}, 204
        
        if data["email"]:
            user_object.user_email = data["email"]
        if data["phone"]:
            user_object.user_phone = data["phone"]

        try:
            # Saving the new user to the database. the method is located in models.py
            user_object.commit()

            return {
                'message': 'User {} was edited'.format(user_object.user_name),
            }, 201
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500

password_parser = reqparse.RequestParser()
password_parser.add_argument('password', help = 'This field cannot be blank', required = True)

## URI: /v1/user/password
class ChangePassword(Resource):
    @jwt_required
    def post(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205
        data = password_parser.parse_args()
        data["password"] = User.generate_hash(data["password"])
        
        # Getting the uid from the jwt.
        current_user = get_jwt_identity()

        # Getting the User from the database through the model in models.py
        user_object = User.find_by_uid(current_user)
        
        # Checks if no object got returned in the query, then return 401 Unauthorized.
        if user_object.user_id == None:
            return {"message": "Invalid uid. The user doesn't exist in our database"}, 204
        if data["password"]:
            user_object.user_password = data["password"]
        
        try:
            # Saving the new user to the database. the method is located in models.py
            user_object.commit()

            return {
                'message': 'Password was edited',
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
            return {'message': 'Not logged in'}, 205
        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the User from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The User doesnt exist in our database"}, 204

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
            return {'message': 'Not logged in'}, 205

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the User from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The User doesnt exist in our database"}, 205
            
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
            return {'message': 'Not logged in'}, 205

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object.user_id == None:
                return {"message": "Invalid uid. The user doesn't exist in our database"}, 205
            
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
            return {'message': 'Not logged in'}, 205

        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object == None:
                return {"message": "Invalid uid. The user doesnt exist in our database"}, 204

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
            return {'message': 'Not logged in'}, 205
        
        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 401 Unauthorized.
            if user_object.user_id == None:
                return {"message": "Invalid uid. The user doesn't exist in our database"}, 204


            return {"message": "user was found", 
                "uid": current_user,
                "email": user_object.user_email,
                "username": user_object.user_name,
                "phone": user_object.user_phone
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500


friend_edit_parser = reqparse.RequestParser()
friend_edit_parser.add_argument('friend_name', help = 'This field cannot be blank', required = True)
friend_edit_parser.add_argument('status', help = 'This field can be blank', required = False)

## URI: /v1/friend
class Friend(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205
        try:
            # Getting the uid from the jwt.
            current_user = get_jwt_identity()

            # Getting the Friend List from the database through the model in models.py
            friend_objects = Friends.find_by_uid(current_user)

            # Checks if no object got returned in the query, then return 404 Not Found.
            if friend_objects == None:
                return {"message": "Error: Friend objects not found"}, 204
            
            friend_list = []

            for friend_object in friend_objects:
                friend_user = User.find_by_uid(friend_object.friend_id)
                friend_list.append({
                    "name": friend_user.user_name, 
                    "status": friend_object.friend_status
                    })

            return {"message": "The uid was found", 
                "uid": current_user,
                "friends": friend_list
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500
    
    @jwt_required
    def post(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205

        current_user = get_jwt_identity()
        data = friend_edit_parser.parse_args()

        if not data["friend_name"]:
            return {'message': 'Friend name is required'}, 203

        friend_user = User.find_by_username(data["friend_name"])
        if friend_user == None:
            return {"message": "Friends user object not found"}, 204

        if not data["status"]:
            return {'message': 'Status is required'}, 203


        try:
            if data["status"] == "send":
                friend_object = Friends.find_by_uid_and_fid(current_user, friend_user.user_id)
                if friend_object != None:
                    return {"message": "Error: Already on list"}, 203
                friends_friend_object = Friends.find_by_uid_and_fid(friend_user.user_id, current_user)
                if friends_friend_object != None:
                    return {"message": "Error: Already on friends list"}, 203

                if friend_user.user_id == current_user:
                    return {"message": "Error: Can't send a request to yourself"}, 203

                own_friend_entry = Friends(
                    user_id = current_user,
                    friend_id = friend_user.user_id,
                    friend_status = "sent"
                )
                friends_friend_entry = Friends(
                    user_id = friend_user.user_id,
                    friend_id = current_user,
                    friend_status = "received"
                )
                own_friend_entry.save_to_db()
                friends_friend_entry.save_to_db()
                return {
                    'message': "Friend request sent."
                }, 201
            
            if data["status"] == "accept":
                friend_object = Friends.find_by_uid_and_fid(current_user, friend_user.user_id)
                if friend_object == None:
                    return {"message": "Friend object not found"}, 204
                friends_friend_object = Friends.find_by_uid_and_fid(friend_user.user_id, current_user)
                if friends_friend_object == None:
                    return {"message": "Friends friend object not found"}, 204
                
                if friend_object.friend_status != "received" or friends_friend_object.friend_status != "sent":
                    return {"message": "Can't accept because there is no request."}, 203

                friend_object.friend_status = "accepted"
                friends_friend_object.friend_status = "accepted"

                friend_object.commit()
                friends_friend_object.commit()
                
                return {
                    'message': "Friend request accepted."
                }, 201
            
            if data["status"] == "delete":
                friend_object = Friends.find_by_uid_and_fid(current_user, friend_user.user_id)
                if friend_object == None:
                    return {"message": "Friend object not found"}, 204
                friends_friend_object = Friends.find_by_uid_and_fid(friend_user.user_id, current_user)
                if friends_friend_object == None:
                    return {"message": "Friends friend object not found"}, 204

                friend_object.delete_from_db()
                friends_friend_object.delete_from_db()

                return {
                    'message': 'Friend entry for friend {} was deleted'.format(friend_user.user_name),
                }, 201

            return {
                'message': "Invalid status."
            }, 201
        except Exception as err:
            return {'message': 'Something went wrong', 
                "error": str(err)
                }, 500


user_exists_parser = reqparse.RequestParser()
user_exists_parser.add_argument('user_name', help = 'This field cannot be blank', required = True)

## URI: /v1/user/exists
class FindByUsername(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205

        try:
            data = user_exists_parser.parse_args()
            if not data["user_name"]:
                return {'message': 'User name is required'}

            # Getting the user from the database through the model in models.py
            user_object = User.find_by_username(data["user_name"])

            # Checks if no object got returned in the query, then return 404 Not Found.
            if user_object == None:
                return {"message": "Invalid username. The user doesnt exist in our database"}, 204

            return {"message": "The user was found", 
                "id": user_object.user_id
                }, 202

        except Exception as err:
            return {"message": "Something went wrong on the server", 
                "error": str(err)
                }, 500

get_trip_parser = reqparse.RequestParser()
get_trip_parser.add_argument('userid', help = 'This field can be blank', required = False)
get_trip_parser.add_argument('tripid', help = "This field can be blank", required = False)

post_trip_parser = reqparse.RequestParser()
post_trip_parser.add_argument('trip', help = 'This field cannot be blank', required = True)
post_trip_parser.add_argument('public', help = 'This field can be blank', required = False)

#URI: /v1/trip
class Trips(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205
        try:
            print("Starting", flush=True)
            current_user = get_jwt_identity()
            userid = request.args.get('userid')
            tripid = request.args.get('tripid')
            print("Got data", flush=True)

            # If a tripid is provided, it will return just that trip
            if (tripid):
                print("tripid was provided", flush=True)
                trip = Trip.find_by_tid(int(tripid))
                print("Found trip", flush=True)
                # Making sure that the user asking for the trip has access to it, either because the user owns it, or is friends with the owner
                isFriends = Friends.find_by_uid_and_fid(current_user, trip.user_id)
                if (trip.user_id != current_user and isFriends == None):
                    print("No access", flush=True)
                    return {
                        "message": "You do not have access to that trip"
                    }, 203
                elif (isFriends.friend_status == "accepted" or trip.user_id == current_user):
                    print("Returning", flush=True)
                    return {
                        "message": "The trip with id {} was found".format(tripid),
                        "trips": [trip.trip_json],
                        "tid": trip.trip_id,
                        "username": User.find_by_uid(trip.user_id).user_name
                    }, 200

            if (not userid):
                userId = current_user
            else:
                userId = userid
            
            if (current_user == userId or Friends.find_by_uid_and_fid(current_user, userId)):
                all_trips = Trip.find_all_public_trips(userId)
                return {
                    "message": "The trips of user {} was found".format(User.find_by_uid(userId).user_name),
                    "trips": json.dumps(all_trips)
                }, 200
            else:
                return {
                    "message": "You are not friends with the requested user, therefore you cannot get their trips"
                }, 203

        except Exception as error:
            return {
                "message": "Something went wrong on the server",
                "error": str(error)
            }, 500

    @jwt_required
    def post(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205
        
        data = post_trip_parser.parse_args()
        print("Test print", flush = True)
        try:
            existing_trip = Trip.does_trip_exist(data["trip"])
            if (existing_trip["exists"]):
                return {
                    "message": "The trip already exist"
                }, 200

            current_user = get_jwt_identity()
            if (not data["public"]):
                public = True
            else:
                public = bool(data["public"])

            if not data["trip"]:
                return {'message': 'You need to provide a trip'}
            else:
                #TODO: Improve this \/
                tid = random.randint(10000000, 99999999)
                while Trip.find_by_tid(tid):
                    if tid >= 99999999:
                        tid = 10000000
                    else:
                        tid += 1
                
                new_trip = Trip(
                    trip_id = tid,
                    user_id = current_user,
                    trip_json = data["trip"],
                    is_public = public
                )
                new_trip.save_to_db()
                return {
                    "message": "The trips was uploaded successfully",
                    "tripid": tid
                }, 201
        except Exception as err:
            return {"message": str(err) }, 500

    @jwt_required
    def put(self):
        #TODO: Update a trip
        try:
            return "god morgne"
        except Exception as err:
            return {"message": "Something went wrong on the server", "error": str(err)}


# URI: /v1/trip/friend
class FriendsTrips(Resource):
    @jwt_required
    def get(self):
        if not WhiteTokenModel.is_jti_whitelisted(get_raw_jwt()["jti"]):
            return {'message': 'Not logged in'}, 205

        try:
            current_user = get_jwt_identity()

            friends = Friends.find_by_uid(current_user)
            if len(friends) == 0:
                return {
                    "message": "You have no friends"
                }, 204

            trips = []

            for friend in friends:
                if friend.friend_status == "accepted":
                    friendUser = User.find_by_uid(friend.friend_id)
                    friendsTrips = Trip.find_all_trips(friend.friend_id)
                    
                    for trip in friendsTrips:
                        tripObject = {
                            "tripid": trip.trip_id,
                            "username": friendUser.user_name,
                            "tripjson": trip.trip_json
                        }
                        trips.append(tripObject)

            return {
                "message": "Your friends' trips were found",
                "trips": trips
            }, 200

        except Exception as error:
            return {
                "message": "Something went wrong on the server",
                "error": error
            }, 500