import bcrypt
from database import UserDatabase

class AuthManager:
    def __init__(self, db: UserDatabase):
        self.db = db

    def hash_password(self, password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def verify_password(self, plain_password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed)

    def register_user(self, username: str, password: str) -> bool:
        hashed = self.hash_password(password)
        return self.db.add_user(username, hashed.decode('utf-8'))

    def authenticate(self, username: str, password: str) -> bool:
        user = self.db.get_user(username)
        if not user:
            return False
        stored_hash = user[2].encode('utf-8')
        return self.verify_password(password, stored_hash)