from run import db
from run import pwd_context

class User(db.Model):
    __tablename__ = "user_table"
    user_id = db.Column(db.Integer, primary_key = True, nullable = False) # pylint: disable=no-member
    user_email = db.Column(db.String(128), unique = True, nullable = False) # pylint: disable=no-member
    user_password = db.Column(db.String(128), unique = False, nullable = True) # pylint: disable=no-member

    user_name = db.Column(db.String(128), unique = False, nullable = True) # pylint: disable=no-member
    user_birthday = db.Column(db.Date, unique = False, nullable = True) # pylint: disable=no-member
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
                'email': x.user_email,
                'user_name': x.user_name,
                'password': x.user_password,
                'birthday': x.user_birthday,
                'phone': x.user_phone,
                'city': None,
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


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True) # pylint: disable=no-member
    jti = db.Column(db.String(128)) # pylint: disable=no-member
    
    def add(self):
        db.session.add(self) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)

