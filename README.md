# Bachelor-Backend
A backend server for the app

## Environment variables needed, either in a .env file or as regular environment variables:
- MySQLPassword - Needs to be the password of the database
- MySQLAddress - The address to the database
- DatabaseName - The name of the database
- Secret - A secret string for flask Secret configuration
- JWTSecret - A secret for the JWT Extended plugin. 


## Routes

### /v1/registration
- POST - Used to registrate a new user
    * Data to send
        - email - The email to register
        - password - The password
        - username - The desired username
        - (optional) phone - The phone number of the user
    * Data to recieve:
        - message - A message that tells you what happened
        - access_token: If successful, you get an access_token that is you token to use while logged in.
    * Status codes
        - 403 - If you provided something invalid
        - 201 - If it was successful
        - 500 - Something went wrong on the server

### /v1/login
- POST - Used to log a user in
    * Data to send: 
        - loginName
        - password
    * Data to recieve
        - message - A message that tells you what happened
        - access_token: If successful, you get an access_token that is you token to use while logged in.
    * Status codes
        - 401 - Wrong loginName or password
        - 202 - Successfully logged in

### /v1/logout
- POST - Used to log the user out
    * No data to send
    * Data to recieve
        - message - Tells you what happened
    * Status codes
        - 200 - Successfully logged out
        - 500 - Something went wrong on the server

### /v1/user - ONLY FOR TESTING
- GET - Used to get info about all the users
    * No data to send
    * Data to recieve
        - List of all users
    * Status codes
        - 200 - Successfully got all users
        - 403 - The server is not in debug mode, and therefore noone has access to this route

- DELETE - Used to delete all users
    * No data to send
    * Data to recieve
        - A message if it was succesful or not
    * Status codes
        - 200 - If it was successful
        - 403 - The server is not in debug mode, and therefore noone has access to this route

### /v1/user/edit
- POST - Used to edit the user (Requiers a bearer token)
    * Data to send
        - (optional) Email
        - (optional) Phone
    * Data to recieve
        - message - Message that says what happened
    * Status codes
        - 201 - The user was successfully edited
        - 404 - The user doesnt exist in the database
        - 500 - Something went wrong on the server

### /v1/user/password
- POST - Used to change the password of the logged in user (Requires a bearer token)
    * Data to send
        - New Password
    * Data to recieve
        - message - What happened
    * Status codes
        - 201 - Password change success
        - 400 - If no password field was sent
        - 401 - Not logged in or invalid account
        - 500 - Something went wrong on the server

### /v1/user/uid
- GET - Used to get the uid (user id) of the user (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - uid - The user id
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the uid
        - 500 - Something went wrong on the server

### /v1/user/email
- GET - Used to get the email of the user (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - email - The email of the user
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the email
        - 500 - Something went wrong on the server
        
### /v1/user/phone
- GET - Used to get the email of the user (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - phone - The phone number of the user
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the phone number
        - 500 - Something went wrong on the server
        
### /v1/user/name
- GET - Used to get the username of the user (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - username - The username of the user
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the username
        - 500 - Something went wrong on the server

### /v1/user/all
- GET - Used to get all information of the user (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - uid - The user id
        - email - The email of the user
        - username - The username of the user
        - phone - The phone number of the user
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the user information
        - 500 - Something went wrong on the server

### /v1/friend
- GET - Used to get the friendlist of the user, including friend requests (Requiers a bearer token)
    * No data to send
    * Data to recieve
        - message - Says what happened
        - friends - The friend list of the user
    * Status codes
        - 401 - Not logged in, or missing bearer token
        - 404 - The user doesnt exist
        - 202 - Successfully found the friend list
        - 500 - Something went wrong on the server

- POST - Used to send a friend request (token required)
    * Data to send 
        - friend_name - The username of the user you want to send a request to
        - status - Specifies what you want to do
            - send - To send a new request
            - accept - To accept a friend request
    * Data to recieve
        - message - What happened
    * Status codes
        - 401 - Not logged in or missing token
        - 404 - The friend doesnt exist
        - 201 - Successfully done the thing

- DELETE - Used to remove a friend or decline a friend request (token required)
    * Data to send
        - friend_name - The username of the "friend"
    * Data to recieve
        - message - What happened
    * Status codes
        - 401 - Not logged in or missing token
        - 404 - The "friend" does not exist
        - 201 - Successfully deleted friend

### v1/user/exists
- GET - Used to check if a user exist (token required)
    * Data to send
        - user_name - The username of the user you want to check
    * Data to recieve
        - message - What happened
        - id - The uid of the user if found
    * Status codes
        - 401 - Not logged in or missing token
        - 202 - The user exists
        - 500 - Server error

### /v1/trip
- GET - Used to get a trip or all trips the user has (token required)
    * Data to send
        - (optional) tripid - The id of the trip. If not specified, gets all the trips
    * Data to recieve
        - message - What happened
        - if tripid was specified: trip - The trip in stringified json
        - if not: trips - Array of all the trips in stringfied json
    * Status codes
        - 401 - Not logged in or missing token
        - 200 - The trip(s) was found

- POST - Used to upload trips
    * Data to send
        - trips - The trips to upload in an array
    * Data to recieve
        - message - What happened
        - trips - The trips ou uploaded with new id and uploaded as true
    * Status codes
        - 401 - Not logged in or missing token
        - 201 - The trip(s) was uploaded
        - 500 - Server error

- PUT - Used to update a trip
    - Comming soon

### /v1/trip/friends
- GET - Used to get your friends' trips
    * Data to recieve
        - message - What happened
        - array of the trips containing:
            * tripid, the id of the trip
            * username, the username of the owner of the trip
            * tripjson, The trip in json
    * Status codes
        - 200 - Successfully got the trips
        - 401 - Not logged in or missing token
        - 404 - You have no friends
        - 500 - Server error