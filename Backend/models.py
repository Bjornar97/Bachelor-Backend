from run import db
from run import pwd_context

class User(db.Model):
    __tablename__ = "user_table"
    user_id = db.Column(db.Integer, primary_key = True, nullable = False) # pylint: disable=no-member
    user_email = db.Column(db.String(128), unique = True, nullable = False) # pylint: disable=no-member
    user_password = db.Column(db.String(128), unique = False, nullable = True) # pylint: disable=no-member
    user_name = db.Column(db.String(128), unique = True, nullable = False) # pylint: disable=no-member
    user_phone = db.Column(db.Integer, unique = False, nullable = True) # pylint: disable=no-member

    @staticmethod
    def generate_hash(password):
        return pwd_context.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return pwd_context.verify(password, hash)

    @classmethod
    def find_by_uid(cls, uid):
        return cls.query.filter_by(user_id = uid).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(user_email = email).first()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(user_name = username).first()
    
    @classmethod
    def number_of_users(cls):
        records = db.session.query(cls).all() # pylint: disable=no-member
        number = len(records)
        return number

    def save_to_db(self):
        db.session.add(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

    def commit(self):
        db.session.commit() # pylint: disable=no-member

    # TODO: Remove this method before production!
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'uid': x.user_id,
                'email': x.user_email,
                'user_name': x.user_name,
                'password': x.user_password,
                'phone': x.user_phone,
                }

        return {'users': list(map(lambda x: to_json(x), User.query.all()))}

    # TODO: Remove this method before production!
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete() # pylint: disable=no-member
            db.session.commit() # pylint: disable=no-member
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception as err:
            return {'message': 'Something went wrong', "error": str(err)}
            

class Friends(db.Model):
    __tablename__ = "friends_table"
    user_id = db.Column(db.Integer, primary_key = True, nullable = False) # pylint: disable=no-member
    friend_id = db.Column(db.Integer, primary_key = True, nullable = False) # pylint: disable=no-member
    friend_status = db.Column(db.String(128), unique = False, nullable = False) # pylint: disable=no-member

    @classmethod
    def find_by_uid(cls, uid):
        return cls.query.filter_by(user_id = uid).all()
        
    @classmethod
    def find_by_uid_and_fid(cls, uid, fid):
        return cls.query.filter_by(user_id = uid, friend_id = fid).first()

    def save_to_db(self):
        db.session.add(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

    def commit(self):
        db.session.commit() # pylint: disable=no-member
        
    def delete_from_db(self):
        db.session.delete(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

    # TODO: Remove this method before production!
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete() # pylint: disable=no-member
            db.session.commit() # pylint: disable=no-member
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception as err:
            return {'message': 'Something went wrong', "error": str(err)}


class WhiteTokenModel(db.Model):
    __tablename__ = 'token_whitelist'
    id = db.Column(db.Integer, primary_key = True) # pylint: disable=no-member
    jti = db.Column(db.String(128)) # pylint: disable=no-member
    
    def add(self):
        db.session.add(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

    @classmethod
    def remove(cls, jti):
        db.session.query(cls).delete() # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

    @classmethod
    def is_jti_whitelisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)


class Trip(db.Model):
    __tablename__ = 'trips_table'
    trip_id = db.Column(db.Integer, primary_key = True, autoincrement=True) # pylint: disable=no-member
    user_id = db.Column(db.Integer, db.ForeignKey('user_table.user_id'), nullable = False) # pylint: disable=no-member
    trip_json = db.Column(db.Text, nullable = True) # pylint: disable=no-member
    is_public = db.Column(db.Boolean, nullable = False) # pylint: disable=no-member

    def save_to_db(self):
        db.session.add(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member
    
    @classmethod
    def remove(cls):
        db.session.query(cls).delete() # pylint: disable=no-member

    @classmethod
    def find_by_tid(cls, tid):
        return cls.query.filter_by(trip_id = tid).first()

    @classmethod
    def find_all_trips(cls, uid):
        return cls.query.filter_by(user_id = uid)

    # Gets all trips from a user that is public
    @classmethod
    def find_all_public_trips(cls, uid):
        return cls.query.filter(cls.user_id == uid, cls.public == True)
    
    @classmethod
    def does_trip_exist(cls, jsonTrip):
        trip = cls.query.filter_by(trip_json = jsonTrip).first()
        return {
            "exists": trip is not None,
            "tid": trip.trip_id
        }
    
